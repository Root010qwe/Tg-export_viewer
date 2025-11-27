# importer/import_telegram.py
from pathlib import Path
from datetime import datetime

from bs4 import BeautifulSoup

from backend.db import SessionLocal, engine
from backend.models import Base, Chat, Message


def parse_date(date_str: str):
    """
    Парсим дату из экспорта Telegram.
    Примеры:
    - "01.01.2020 12:34:56"
    - "01.01.2020 12:34:56 UTC+3"
    """
    if not date_str:
        return None

    if " UTC" in date_str:
        date_str = date_str.split(" UTC", 1)[0]

    for fmt in ("%d.%m.%Y %H:%M:%S", "%d.%m.%Y %H:%M"):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    return None


def detect_media_in_message(msg_div):
    """
    Поиск медиа по ссылкам внутри одного сообщения.
    Ищем href, которые начинаются с:
      photos/, video/, files/, voice/, audio/, stickers/, images/, round_video_messages/
    """
    media_link = None

    for a in msg_div.find_all("a", href=True):
        href = a["href"]
        lower = href.lower()
        if lower.startswith((
            "photos/",
            "video/",
            "files/",
            "voice/",
            "audio/",
            "audios/",
            "stickers/",
            "images/",
            "round_video_messages/",
            "video_files/",
        )):
            media_link = href
            break

    if not media_link:
        return False, None, None

    lower = media_link.lower()

    if lower.endswith((".jpg", ".jpeg", ".png", ".webp", ".gif")):
        media_type = "photo"
    elif lower.endswith((".mp4", ".mov", ".mkv", ".webm")):
        media_type = "video"
    elif lower.endswith((".ogg", ".mp3", ".wav", ".m4a")):
        media_type = "audio"
    else:
        media_type = "file"

    return True, media_type, media_link


def update_chat_title_from_html(chat: Chat, first_html_file: Path, db: SessionLocal):
    """
    Пытаемся вытащить нормальное имя чата из первого HTML:
    обычно оно в .page_header .title или .page_title.
    """
    try:
        with first_html_file.open("r", encoding="utf-8") as f:
            soup = BeautifulSoup(f, "html.parser")
        title_el = soup.select_one(".page_header .title") or soup.select_one(".page_title")
        if title_el:
            title_text = title_el.get_text(strip=True)
            if title_text:
                chat.title = title_text
                db.commit()
                print(f"  Обновили название чата: {chat.title}")
    except Exception as e:
        print(f"  Не удалось обновить заголовок чата: {e}")


def import_chat_folder(folder: Path, db: SessionLocal, user_id: int = None):
    """
    Импорт одной папки с экспортом чата.
    user_id: ID пользователя, которому принадлежит чат (обязательно при создании нового чата)
    """
    print(f"=== Импорт чата из папки: {folder.name} ===")

    chat = db.query(Chat).filter_by(export_folder=folder.name).first()
    if chat:
        print(f"Чат уже есть в базе: {chat.title} (id={chat.id})")
        # Обновляем user_id, если он был передан и чат еще не привязан к пользователю
        if user_id and not chat.user_id:
            chat.user_id = user_id
            db.commit()
    else:
        # user_id обязателен при создании нового чата
        if not user_id:
            raise ValueError("user_id обязателен при создании нового чата")
        chat = Chat(
            title=folder.name,
            export_folder=folder.name,
            user_id=user_id,
        )
        db.add(chat)
        db.commit()
        db.refresh(chat)
        print(f"Создан новый чат: {chat.title} (id={chat.id})")

    html_files = sorted(folder.glob("messages*.html"))
    if not html_files:
        print("  Нет файлов messages*.html, пропускаем.")
        return

    # Обновим название чата из первого файла, если получится
    if chat.title == folder.name:
        update_chat_title_from_html(chat, html_files[0], db)

    min_date = None
    max_date = None
    imported_count = 0
    skipped_duplicates = 0

    # Счётчик порядка сообщений
    order_counter = 0

    for html_file in html_files:
        print(f"  Обработка файла: {html_file.name}")
        with html_file.open("r", encoding="utf-8") as f:
            soup = BeautifulSoup(f, "html.parser")

        message_divs = soup.select("div.message")
        print(f"    Найдено блоков сообщений: {len(message_divs)}")

        for msg_div in message_divs:
            raw_html = str(msg_div)

            msg_id_raw = msg_div.get("id", "")
            telegram_msg_id = None
            if msg_id_raw.startswith("message"):
                try:
                    telegram_msg_id = int(msg_id_raw.replace("message", ""))
                except ValueError:
                    telegram_msg_id = None

            if telegram_msg_id is not None:
                exists = (
                    db.query(Message)
                    .filter(
                        Message.chat_id == chat.id,
                        Message.telegram_message_id == telegram_msg_id,
                    )
                    .first()
                )
                if exists:
                    skipped_duplicates += 1
                    continue

            # дата
            date_div = msg_div.select_one("div.date")
            date = None
            if date_div is not None:
                date_title = date_div.get("title") or date_div.get("data-title")
                date = parse_date(date_title)

            # отправитель
            from_div = msg_div.select_one(".from_name")
            sender = from_div.get_text(strip=True) if from_div else None

            # текст (для поиска)
            text_div = msg_div.select_one(".text")
            text_clean = text_div.get_text("\n", strip=True) if text_div else None

            # медиа (для информации)
            has_media, media_type, media_path = detect_media_in_message(msg_div)

            msg = Message(
                chat_id=chat.id,
                telegram_message_id=telegram_msg_id,
                sender=sender,
                date=date,
                order_index=order_counter,
                text=text_clean,
                raw_html=raw_html,
                has_media=has_media,
                media_type=media_type,
                media_path=media_path,
            )
            db.add(msg)
            imported_count += 1
            order_counter += 1

            if date:
                if min_date is None or date < min_date:
                    min_date = date
                if max_date is None or date > max_date:
                    max_date = date

        db.commit()

    if min_date:
        chat.created_at = min_date
    if max_date:
        chat.updated_at = max_date
    db.commit()

    print(f"  Импортировано сообщений: {imported_count}")
    print(f"  Пропущено дубликатов: {skipped_duplicates}")
    print(f"=== Готово: {chat.title} ===\n")



def main():
    from backend.models import User
    import hashlib
    
    Base.metadata.create_all(bind=engine)

    exports_root = Path("data/exports_raw")
    if not exports_root.exists():
        print("Папка data/exports_raw не найдена.")
        return

    db = SessionLocal()
    try:
        # Создаём дефолтного админа, если его нет
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            password_salt = "telegram_memory_salt_2025"
            password_hash = hashlib.sha256((password_salt + "admin").encode("utf-8")).hexdigest()
            admin = User(
                username="admin",
                password_hash=password_hash,
                is_admin=True,
                created_at=datetime.now(),
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
            print(f"Создан дефолтный админ: admin / admin")
        
        for folder in exports_root.iterdir():
            if folder.is_dir():
                import_chat_folder(folder, db, user_id=admin.id)
    finally:
        db.close()


if __name__ == "__main__":
    main()
