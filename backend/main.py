# backend/main.py
import os
import json
import zipfile
import tempfile
import re
import bcrypt
from datetime import datetime, date, time
from pathlib import Path
from typing import Optional

from fastapi import (
    FastAPI,
    Request,
    Depends,
    Query,
    HTTPException,
    File,
    UploadFile,
    Form,
    status,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
# Rate limiting будет добавлен позже при необходимости
# from slowapi import Limiter, _rate_limit_exceeded_handler
# from slowapi.util import get_remote_address
# from slowapi.errors import RateLimitExceeded

from .db import SessionLocal, engine
from .models import Base, Chat, Message, User, ChatAccess
from importer.import_telegram import import_chat_folder

# ===== БАЗА =====
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Telegram Memory Reader")

# Rate limiting - можно добавить позже при необходимости
# limiter = Limiter(key_func=get_remote_address)
# app.state.limiter = limiter
# app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Статика
app.mount("/static", StaticFiles(directory="backend/static"), name="static")
app.mount("/exports", StaticFiles(directory="data/exports_raw"), name="exports")

templates = Jinja2Templates(directory="backend/templates")

# Константы безопасности
MAX_USERNAME_LENGTH = 50
MIN_USERNAME_LENGTH = 3
MIN_PASSWORD_LENGTH = 8
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

# Обработчик для редиректа на страницу входа при 401
@app.exception_handler(HTTPException)
async def auth_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        return RedirectResponse("/login", status_code=303)
    raise exc


def hash_password(password: str) -> str:
    """Хэширует пароль с помощью bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Проверяет пароль против хэша"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False


# Мастер-пароль задаётся через переменную окружения TGMEM_MASTER_PASSWORD
MASTER_PASSWORD = os.getenv("TGMEM_MASTER_PASSWORD")
MASTER_PASSWORD_HASH = hash_password(MASTER_PASSWORD) if MASTER_PASSWORD else None


def validate_username(username: str) -> tuple[bool, Optional[str]]:
    """Валидация имени пользователя. Возвращает (is_valid, error_message)"""
    if len(username) < MIN_USERNAME_LENGTH:
        return False, f"Имя пользователя должно быть не менее {MIN_USERNAME_LENGTH} символов"
    if len(username) > MAX_USERNAME_LENGTH:
        return False, f"Имя пользователя должно быть не более {MAX_USERNAME_LENGTH} символов"
    if not USERNAME_PATTERN.match(username):
        return False, "Имя пользователя может содержать только буквы, цифры, дефисы и подчёркивания"
    return True, None


def validate_password(password: str) -> tuple[bool, Optional[str]]:
    """Валидация пароля. Возвращает (is_valid, error_message)"""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Пароль должен быть не менее {MIN_PASSWORD_LENGTH} символов"
    if len(password) > 128:
        return False, "Пароль слишком длинный"
    return True, None


def set_auth_cookie(response: RedirectResponse, user_id: int):
    """Устанавливает безопасную cookie для аутентификации"""
    response.set_cookie(
        "tgmem_user_id",
        str(user_id),
        httponly=True,
        secure=True,  # Только HTTPS
        samesite="lax",  # Защита от CSRF
        max_age=60 * 60 * 24 * 30,  # 30 дней
    )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ===== АУТЕНТИФИКАЦИЯ =====
def get_current_user(request: Request, db: Session = Depends(get_db)):
    """Получить текущего пользователя из сессии"""
    user_id = request.cookies.get("tgmem_user_id")
    if not user_id:
        return None
    try:
        user = db.query(User).filter(User.id == int(user_id)).first()
        return user
    except (ValueError, TypeError):
        return None


def require_auth(current_user: User = Depends(get_current_user)):
    """Зависимость для маршрутов, требующих аутентификации"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    return current_user


def require_admin(current_user: User = Depends(require_auth)):
    """Зависимость для маршрутов, требующих прав администратора"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    return current_user


def has_chat_access(db: Session, user: User, chat: Chat) -> bool:
    """Проверяет, есть ли у пользователя доступ к чату"""
    # Админ имеет доступ ко всем чатам
    if user.is_admin:
        return True
    # Владелец чата имеет доступ
    if chat.user_id == user.id:
        return True
    # Проверяем явно выданный доступ
    access = db.query(ChatAccess).filter(
        ChatAccess.user_id == user.id,
        ChatAccess.chat_id == chat.id
    ).first()
    return access is not None


# ===== СЕРВИСНЫЙ РОУТ ДЛЯ ПРОВЕРКИ =====
@app.get("/ping")
def ping():
    return {"status": "ok"}


# ===== АУТЕНТИФИКАЦИЯ: вход =====
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, error: str = None, current_user: User = Depends(get_current_user)):
    # Если уже авторизован, редиректим на главную
    if current_user:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": error, "current_user": None},
    )


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
):
    # Валидация username
    is_valid, error_msg = validate_username(username)
    if not is_valid:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": error_msg, "current_user": None},
        )
    
    user = db.query(User).filter(User.username == username).first()
    # Всегда выполняем проверку пароля для защиты от timing attacks
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверное имя пользователя или пароль", "current_user": None},
        )
    
    response = RedirectResponse("/?success=Вход выполнен успешно", status_code=303)
    set_auth_cookie(response, user.id)
    return response


# ===== АУТЕНТИФИКАЦИЯ: регистрация =====
@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request, error: str = None, current_user: User = Depends(get_current_user)):
    # Если уже авторизован, редиректим на главную
    if current_user:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "error": error, "current_user": None},
    )


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    # Валидация паролей
    if password != password_confirm:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Пароли не совпадают", "current_user": None},
        )
    
    # Валидация username
    is_valid, error_msg = validate_username(username)
    if not is_valid:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": error_msg, "current_user": None},
        )
    
    # Валидация password
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": error_msg, "current_user": None},
        )
    
    # Проверяем, существует ли пользователь
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Пользователь с таким именем уже существует", "current_user": None},
        )
    
    # Создаём первого пользователя как админа
    is_first_user = db.query(User).count() == 0
    
    new_user = User(
        username=username.strip(),
        password_hash=hash_password(password),
        is_admin=is_first_user,
        created_at=datetime.now(),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    response = RedirectResponse("/?success=Регистрация выполнена успешно", status_code=303)
    set_auth_cookie(response, new_user.id)
    return response


# ===== АУТЕНТИФИКАЦИЯ: выход =====
@app.post("/logout", response_class=HTMLResponse)
def logout():
    response = RedirectResponse("/login?success=Выход выполнен", status_code=303)
    response.delete_cookie("tgmem_user_id", secure=True, samesite="lax")
    return response


# ===== ГЛАВНАЯ: список чатов =====
@app.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auth),
):
    # Админ видит все чаты, обычный пользователь - свои + с выданным доступом
    if current_user.is_admin:
        chats = (
            db.query(Chat)
            .order_by(Chat.title.asc())
            .all()
        )
        chat_access_map = {}  # Для админа не нужно
    else:
        # Получаем ID чатов с выданным доступом
        access_chat_ids = [
            access.chat_id for access in db.query(ChatAccess.chat_id)
            .filter(ChatAccess.user_id == current_user.id)
            .all()
        ]
        # Свои чаты + чаты с доступом
        chats = (
            db.query(Chat)
            .filter(
                (Chat.user_id == current_user.id) |
                (Chat.id.in_(access_chat_ids))
            )
            .order_by(Chat.title.asc())
            .all()
        )
        # Создаём карту доступа для отображения
        chat_access_map = {chat_id: True for chat_id in access_chat_ids}
    
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "chats": chats,
            "current_user": current_user,
            "chat_access_map": chat_access_map,
        },
    )


# ===== ЧАТ: просмотр (с проверкой пароля) =====
@app.get("/chats/{chat_id}", response_class=HTMLResponse)
def view_chat(
    chat_id: int,
    request: Request,
    db: Session = Depends(get_db),
    order: str = Query("asc"),
    current_user: User = Depends(require_auth),
):
    order = (order or "asc").lower()
    if order not in ("asc", "desc"):
        order = "asc"

    chat = db.query(Chat).get(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    # Проверяем доступ
    if not has_chat_access(db, current_user, chat):
        raise HTTPException(status_code=403, detail="Доступ запрещён")

    # проверяем, нужен ли пароль
    if chat.password_hash:
        cookie_name = f"tgmem_chat_{chat_id}"
        cookie_value = request.cookies.get(cookie_name)
        if cookie_value != chat.password_hash:
            # показываем страницу ввода пароля
            return templates.TemplateResponse(
                "chat_lock.html",
                {
                    "request": request,
                    "chat": chat,
                    "order": order,
                    "error": None,
                    "current_user": current_user,
                },
            )

    query = db.query(Message).filter(Message.chat_id == chat_id)

    if order == "desc":
        query = query.order_by(Message.order_index.desc(), Message.id.desc())
    else:
        query = query.order_by(Message.order_index.asc(), Message.id.asc())

    messages = query.all()
    total = len(messages)

    # данные для выбора дат
    years_set = set()
    months_by_year = {}
    days_by_year_month = {}

    for m in messages:
        if not m.date:
            continue
        y = m.date.year
        mo = m.date.month
        d = m.date.day

        years_set.add(y)
        months_by_year.setdefault(y, set()).add(mo)
        days_by_year_month.setdefault((y, mo), set()).add(d)

    available_dates = {
        "years": sorted(years_set),
        "months": {
            str(y): sorted(list(months_by_year.get(y, [])))
            for y in years_set
        },
        "days": {
            f"{y}-{m}": sorted(list(days_by_year_month.get((y, m), [])))
            for (y, m) in days_by_year_month.keys()
        },
    }
    available_dates_json = json.dumps(available_dates, ensure_ascii=False)

    return templates.TemplateResponse(
        "chat_view.html",
        {
            "request": request,
            "chat": chat,
            "messages": messages,
            "total": total,
            "order": order,
            "available_dates_json": available_dates_json,
            "current_user": current_user,
        },
    )


# ===== Разблокировка чата по паролю =====
@app.post("/chats/{chat_id}/unlock", response_class=HTMLResponse)
async def unlock_chat(
    chat_id: int,
    request: Request,
    password: str = Form(...),
    order: str = Form("asc"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auth),
):
    chat = db.query(Chat).get(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    # Проверяем доступ
    if not has_chat_access(db, current_user, chat):
        raise HTTPException(status_code=403, detail="Доступ запрещён")

    # если пароля у чата нет — просто отправляем в чат
    if not chat.password_hash and not MASTER_PASSWORD_HASH:
        return RedirectResponse(f"/chats/{chat_id}?order={order}", status_code=303)

    valid = False

    # 1) проверяем пароль чата, если он есть
    if chat.password_hash and verify_password(password, chat.password_hash):
        valid = True

    # 2) если не подошёл, проверяем мастер-пароль (если задан)
    if not valid and MASTER_PASSWORD_HASH and verify_password(password, MASTER_PASSWORD_HASH):
        valid = True

    if not valid:
        # неверный пароль — показываем форму с ошибкой
        return templates.TemplateResponse(
            "chat_lock.html",
            {
                "request": request,
                "chat": chat,
                "order": order,
                "error": "Неверный пароль",
                "current_user": current_user,
            },
        )

    # пароль верный (либо чатовый, либо мастер) — ставим cookie и редиректим
    cookie_name = f"tgmem_chat_{chat_id}"
    response = RedirectResponse(f"/chats/{chat_id}?order={order}", status_code=303)

    # cookie одинаковая для любого способа входа: просто хэш пароля чата,
    # чтобы дальше не вводить пароль заново
    if chat.password_hash:
        cookie_value = chat.password_hash
    else:
        # если у чата нет собственного пароля, но есть только мастер — просто ставим master_hash
        cookie_value = MASTER_PASSWORD_HASH or ""

    response.set_cookie(
        cookie_name,
        cookie_value,
        httponly=True,
        max_age=60 * 60 * 24 * 365,  # год
    )
    return response



# ===== Поиск по тексту =====
@app.get("/chats/{chat_id}/search", response_class=HTMLResponse)
def search_chat(
    chat_id: int,
    request: Request,
    db: Session = Depends(get_db),
    q: str = Query(..., min_length=2),
    current_user: User = Depends(require_auth),
):
    chat = db.query(Chat).get(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    # Проверяем доступ
    if not has_chat_access(db, current_user, chat):
        raise HTTPException(status_code=403, detail="Доступ запрещён")

    # если чат защищён и нет cookie — перекидываем на основной просмотр,
    # он сам покажет форму пароля
    if chat.password_hash:
        cookie_name = f"tgmem_chat_{chat_id}"
        cookie_value = request.cookies.get(cookie_name)
        if cookie_value != chat.password_hash:
            return RedirectResponse(f"/chats/{chat_id}", status_code=303)

    results = (
        db.query(Message)
        .filter(
            Message.chat_id == chat_id,
            Message.text.isnot(None),
            Message.text.contains(q),
        )
        .order_by(Message.date.asc(), Message.id.asc())
        .limit(300)
        .all()
    )

    return templates.TemplateResponse(
        "search_results.html",
        {
            "request": request,
            "chat": chat,
            "query": q,
            "results": results,
            "current_user": current_user,
        },
    )


# ===== Переход к дате =====
@app.get("/chats/{chat_id}/by_date")
def go_to_date(
    chat_id: int,
    date: date,
    order: str = Query("asc"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auth),
):
    order = (order or "asc").lower()
    if order not in ("asc", "desc"):
        order = "asc"

    chat = db.query(Chat).get(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    # Проверяем доступ
    if not has_chat_access(db, current_user, chat):
        raise HTTPException(status_code=403, detail="Доступ запрещён")

    # Защита: требуем уже разблокированный чат
    if chat.password_hash:
        # тут Request недоступен, поэтому просто редиректим на просмотр,
        # он сам покажет форму
        return RedirectResponse(f"/chats/{chat_id}", status_code=303)

    dt_start = datetime.combine(date, time.min)
    dt_end = datetime.combine(date, time.max)

    # Ищем первое сообщение в выбранный день
    # Если order=asc, ищем первое сообщение >= начала дня
    # Если order=desc, ищем последнее сообщение <= конца дня
    if order == "desc":
        msg = (
            db.query(Message)
            .filter(
                Message.chat_id == chat_id,
                Message.date.isnot(None),
                Message.date <= dt_end,
            )
            .order_by(Message.date.desc(), Message.id.desc())
            .first()
        )
    else:
        msg = (
            db.query(Message)
            .filter(
                Message.chat_id == chat_id,
                Message.date.isnot(None),
                Message.date >= dt_start,
            )
            .order_by(Message.date.asc(), Message.id.asc())
            .first()
        )

    anchor = ""
    if msg and msg.telegram_message_id is not None:
        anchor = f"#message{msg.telegram_message_id}"

    url = f"/chats/{chat_id}?order={order}{anchor}"
    return RedirectResponse(url, status_code=303)


# ===== Импорт чата через интерфейс (.zip) =====
@app.get("/import", response_class=HTMLResponse)
def import_form(
    request: Request,
    current_user: User = Depends(require_auth),
):
    return templates.TemplateResponse(
        "import.html",
        {"request": request, "current_user": current_user},
    )


@app.post("/import", response_class=HTMLResponse)
async def import_upload(
    request: Request,
    db: Session = Depends(get_db),
    file: UploadFile = File(...),
    title: str = Form(""),
    current_user: User = Depends(require_auth),
):
    filename = file.filename or ""
    if not filename.lower().endswith(".zip"):
        return templates.TemplateResponse(
            "import.html",
            {
                "request": request,
                "current_user": current_user,
                "error": "Нужен .zip-файл экспорта Telegram (HTML-режим).",
            },
        )

    contents = await file.read()

    # Валидация названия чата
    if title.strip() and len(title.strip()) > 200:
        return templates.TemplateResponse(
            "import.html",
            {
                "request": request,
                "current_user": current_user,
                "error": "Название чата слишком длинное (максимум 200 символов).",
            },
        )

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "upload.zip")
            with open(zip_path, "wb") as f:
                f.write(contents)

            with zipfile.ZipFile(zip_path, "r") as zf:
                namelist = zf.namelist()
                if not namelist:
                    return templates.TemplateResponse(
                        "import.html",
                        {
                            "request": request,
                            "current_user": current_user,
                            "error": "Архив пустой.",
                        },
                    )

                first = namelist[0]
                root_dir = first.split("/")[0]  # обычно ChatExport_...
                
                # Защита от path traversal
                if ".." in root_dir or "/" in root_dir or "\\" in root_dir:
                    return templates.TemplateResponse(
                        "import.html",
                        {
                            "request": request,
                            "current_user": current_user,
                            "error": "Некорректное имя папки в архиве.",
                        },
                    )
                
                # Проверяем, что все файлы в архиве находятся внутри root_dir
                for name in namelist:
                    if ".." in name or not name.startswith(root_dir + "/"):
                        return templates.TemplateResponse(
                            "import.html",
                            {
                                "request": request,
                                "current_user": current_user,
                                "error": "Архив содержит небезопасные пути.",
                            },
                        )

                target_root = Path("data/exports_raw")
                target_root.mkdir(parents=True, exist_ok=True)

                zf.extractall(target_root)

        folder_path = Path("data/exports_raw") / root_dir
        if not folder_path.exists() or not folder_path.is_dir():
            return templates.TemplateResponse(
                "import.html",
                {
                    "request": request,
                    "current_user": current_user,
                    "error": "Не удалось найти папку экспорта после распаковки.",
                },
            )

        # импортируем сообщения (передаём user_id для создания чата)
        try:
            import_chat_folder(folder_path, db, user_id=current_user.id)
        except Exception as e:
            return templates.TemplateResponse(
                "import.html",
                {
                    "request": request,
                    "current_user": current_user,
                    "error": f"Ошибка при импорте: {str(e)}",
                },
            )

        # находим чат
        chat = db.query(Chat).filter_by(export_folder=root_dir).first()
        if chat:
            # Обновляем чат: привязываем к текущему пользователю, задаём название
            chat.user_id = current_user.id
            if title.strip():
                chat.title = title.strip()[:200]  # Ограничение длины
            # Пароль больше не устанавливается при импорте
            db.add(chat)
            db.commit()
        else:
            return templates.TemplateResponse(
                "import.html",
                {
                    "request": request,
                    "current_user": current_user,
                    "error": "Ошибка: чат не был создан после импорта.",
                },
            )

        # после импорта открываем список чатов
        return RedirectResponse("/?success=Чат успешно импортирован", status_code=303)
    
    except zipfile.BadZipFile:
        return templates.TemplateResponse(
            "import.html",
            {
                "request": request,
                "current_user": current_user,
                "error": "Некорректный ZIP-архив.",
            },
        )
    except Exception as e:
        return templates.TemplateResponse(
            "import.html",
            {
                "request": request,
                "current_user": current_user,
                "error": f"Ошибка при обработке файла: {str(e)}",
            },
        )


# ===== Переименование чата =====
@app.get("/chats/{chat_id}/edit", response_class=HTMLResponse)
def edit_chat(
    chat_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auth),
):
    chat = db.query(Chat).get(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    # Проверяем доступ (только владелец или админ может редактировать)
    if not current_user.is_admin and chat.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Доступ запрещён")

    return templates.TemplateResponse(
        "chat_edit.html",
        {"request": request, "chat": chat, "current_user": current_user},
    )


@app.post("/chats/{chat_id}/edit", response_class=HTMLResponse)
async def edit_chat_post(
    chat_id: int,
    request: Request,
    title: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auth),
):
    chat = db.query(Chat).get(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    # Проверяем доступ (только владелец или админ может редактировать)
    if not current_user.is_admin and chat.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Доступ запрещён")

    chat.title = title.strip() or chat.title
    db.add(chat)
    db.commit()

    return RedirectResponse(f"/chats/{chat_id}", status_code=303)


# ===== АДМИН-ПАНЕЛЬ: Управление пользователями =====
@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "users": users, "current_user": current_user},
    )


@app.post("/admin/users/{user_id}/toggle_admin", response_class=HTMLResponse)
def toggle_admin(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    # Нельзя снять права админа у самого себя
    if user_id == current_user.id:
        return RedirectResponse("/admin/users?error=Нельзя снять права админа у самого себя", status_code=303)
    
    user = db.query(User).get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_admin = not user.is_admin
    db.add(user)
    db.commit()
    
    return RedirectResponse("/admin/users", status_code=303)


@app.post("/admin/users/{user_id}/delete", response_class=HTMLResponse)
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    # Нельзя удалить самого себя
    if user_id == current_user.id:
        return RedirectResponse("/admin/users?error=Нельзя удалить самого себя", status_code=303)
    
    user = db.query(User).get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Проверяем, есть ли у пользователя чаты
    user_chats_count = db.query(Chat).filter(Chat.user_id == user_id).count()
    if user_chats_count > 0:
        return RedirectResponse(
            f"/admin/users?error=Нельзя удалить пользователя с {user_chats_count} чатом(ами). Сначала передайте чаты другому пользователю.",
            status_code=303
        )
    
    # Удаляем доступы пользователя
    db.query(ChatAccess).filter(ChatAccess.user_id == user_id).delete()
    
    db.delete(user)
    db.commit()
    
    return RedirectResponse("/admin/users?success=Пользователь успешно удалён", status_code=303)


# ===== АДМИН-ПАНЕЛЬ: Управление доступом к чатам =====
@app.get("/admin/chat-access", response_class=HTMLResponse)
def admin_chat_access(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    user_id: int = Query(None),
):
    users = db.query(User).order_by(User.username.asc()).all()
    chats = db.query(Chat).order_by(Chat.title.asc()).all()
    
    selected_user = None
    user_chats = []
    available_chats = []
    
    if user_id:
        selected_user = db.query(User).get(user_id)
        if selected_user:
            # Чаты пользователя (свои + с доступом)
            user_chat_ids = set()
            # Свои чаты
            user_chats_owned = db.query(Chat.id).filter(Chat.user_id == selected_user.id).all()
            user_chat_ids.update([c.id for c in user_chats_owned])
            # Чаты с доступом
            user_accesses = db.query(ChatAccess.chat_id).filter(ChatAccess.user_id == selected_user.id).all()
            user_chat_ids.update([a.chat_id for a in user_accesses])
            
            user_chats = db.query(Chat).filter(Chat.id.in_(user_chat_ids)).order_by(Chat.title.asc()).all()
            available_chats = db.query(Chat).filter(~Chat.id.in_(user_chat_ids)).order_by(Chat.title.asc()).all()
    
    return templates.TemplateResponse(
        "admin_chat_access.html",
        {
            "request": request,
            "users": users,
            "chats": chats,
            "selected_user": selected_user,
            "user_chats": user_chats,
            "available_chats": available_chats,
            "current_user": current_user,
        },
    )


@app.post("/admin/chat-access/grant", response_class=HTMLResponse)
def grant_chat_access(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    user_id: int = Form(...),
    chat_id: int = Form(...),
):
    user = db.query(User).get(user_id)
    chat = db.query(Chat).get(chat_id)
    
    if not user or not chat:
        raise HTTPException(status_code=404, detail="User or Chat not found")
    
    # Проверяем, нет ли уже доступа
    existing = db.query(ChatAccess).filter(
        ChatAccess.user_id == user_id,
        ChatAccess.chat_id == chat_id
    ).first()
    
    if not existing:
        access = ChatAccess(
            user_id=user_id,
            chat_id=chat_id,
            granted_at=datetime.now(),
            granted_by=current_user.id,
        )
        db.add(access)
        db.commit()
    
    return RedirectResponse(f"/admin/chat-access?user_id={user_id}", status_code=303)


@app.post("/admin/chat-access/revoke", response_class=HTMLResponse)
def revoke_chat_access(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    user_id: int = Form(...),
    chat_id: int = Form(...),
):
    # Нельзя отозвать доступ к своему чату
    chat = db.query(Chat).get(chat_id)
    if chat and chat.user_id == user_id:
        return RedirectResponse(f"/admin/chat-access?user_id={user_id}&error=Нельзя отозвать доступ к своему чату", status_code=303)
    
    access = db.query(ChatAccess).filter(
        ChatAccess.user_id == user_id,
        ChatAccess.chat_id == chat_id
    ).first()
    
    if access:
        db.delete(access)
        db.commit()
    
    return RedirectResponse(f"/admin/chat-access?user_id={user_id}", status_code=303)
