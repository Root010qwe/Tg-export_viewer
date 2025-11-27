// backend/static/js/chat.js

document.addEventListener("DOMContentLoaded", () => {
  const body = document.body;

  // ===== ТЕМА =====
  const THEME_KEY = "tgmem_theme";

  function applyInitialTheme() {
    const saved = localStorage.getItem(THEME_KEY);

    if (saved === "dark") {
      body.classList.add("tgmem-dark");
      return;
    }
    if (saved === "light") {
      body.classList.remove("tgmem-dark");
      return;
    }

    // По умолчанию — тёмная
    body.classList.add("tgmem-dark");
  }

  applyInitialTheme();

  const themeBtn = document.getElementById("tgmem-toggle-theme");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const nowDark = body.classList.toggle("tgmem-dark");
      localStorage.setItem(THEME_KEY, nowDark ? "dark" : "light");
    });
  }

  // ===== СКРОЛЛ В НАЧАЛО / В КОНЕЦ =====
  const historyEl = document.querySelector(".history");
  const scrollTopBtn = document.getElementById("tgmem-scroll-top");
  const scrollBottomBtn = document.getElementById("tgmem-scroll-bottom");

  function scrollToTop() {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function scrollToBottom() {
    window.scrollTo({ top: document.body.scrollHeight, behavior: "smooth" });
  }

  if (scrollTopBtn) {
    scrollTopBtn.addEventListener("click", (e) => {
      e.preventDefault();
      scrollToTop();
    });
  }

  if (scrollBottomBtn) {
    scrollBottomBtn.addEventListener("click", (e) => {
      e.preventDefault();
      scrollToBottom();
    });
  }

  // Автопрокрутка при загрузке только если явно указано
  // Отключено при смене сортировки, чтобы не мешать пользователю
  // Но если есть якорь в URL (например, при переходе к дате), прокручиваем к нему
  if (historyEl) {
    const auto = historyEl.getAttribute("data-auto-scroll");
    const urlParams = new URLSearchParams(window.location.search);
    const hasOrderParam = urlParams.has('order');
    const hasHash = window.location.hash && window.location.hash.startsWith('#message');
    
    // Если есть якорь (переход к конкретному сообщению), не используем автоскролл
    // Якорь обрабатывается отдельно ниже и имеет приоритет
    if (!hasHash && !hasOrderParam) {
      // Автопрокручиваем только если нет параметра order и нет якоря (первая загрузка)
      if (auto === "bottom") {
        // Небольшая задержка для корректной прокрутки
        setTimeout(() => scrollToBottom(), 100);
      } else if (auto === "top") {
        setTimeout(() => scrollToTop(), 100);
      }
    }
  }

  // ===== УМНЫЙ ПОИСК ПО ДАТЕ: ГОД / МЕСЯЦ / ДЕНЬ =====
    // ===== УМНЫЙ ПОИСК ПО ДАТЕ: ГОД / МЕСЯЦ / ДЕНЬ =====
  function initDateSelectors() {
    // Берём JSON из <script id="tg-available-dates" type="application/json">
    const dataScript = document.getElementById("tg-available-dates");
    if (!dataScript) return;

    let data;
    try {
      // textContent содержит наш JSON вида {"years":[2020,...], "months": {...}, "days": {...}}
      const jsonText = dataScript.textContent || dataScript.innerText || "{}";
      data = JSON.parse(jsonText);
    } catch (e) {
      console.error("Ошибка разбора TG_AVAILABLE_DATES:", e);
      return;
    }

    const years = data.years || [];
    const months = data.months || {};
    const days = data.days || {};

    const yearSelect = document.getElementById("tg-year-select");
    const monthSelect = document.getElementById("tg-month-select");
    const daySelect = document.getElementById("tg-day-select");
    const dateInput = document.getElementById("tg-date-input");
    const form = document.getElementById("tgmem-date-form");

    if (!yearSelect || !monthSelect || !daySelect || !dateInput || !form) {
      return;
    }

    // Заполняем список годов
    years
      .slice()          // на всякий случай копия
      .sort((a, b) => a - b)
      .forEach((y) => {
        const opt = document.createElement("option");
        opt.value = String(y);
        opt.textContent = String(y);
        yearSelect.appendChild(opt);
      });

    function clearSelect(select, placeholder) {
      select.innerHTML = "";
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = placeholder;
      select.appendChild(opt);
    }

    yearSelect.addEventListener("change", () => {
      const y = yearSelect.value;
      clearSelect(monthSelect, "Месяц");
      clearSelect(daySelect, "День");
      monthSelect.disabled = true;
      daySelect.disabled = true;

      if (!y || !months[y]) return;

      months[y].forEach((m) => {
        const opt = document.createElement("option");
        opt.value = String(m);
        opt.textContent = String(m).padStart(2, "0");
        monthSelect.appendChild(opt);
      });

      monthSelect.disabled = false;
    });

    monthSelect.addEventListener("change", () => {
      const y = yearSelect.value;
      const m = monthSelect.value;
      clearSelect(daySelect, "День");
      daySelect.disabled = true;

      if (!y || !m) return;
      const key = `${y}-${m}`;
      const ds = days[key];
      if (!ds || !ds.length) return;

      ds.forEach((d) => {
        const opt = document.createElement("option");
        opt.value = String(d);
        opt.textContent = String(d).padStart(2, "0");
        daySelect.appendChild(opt);
      });

      daySelect.disabled = false;
    });

    form.addEventListener("submit", (e) => {
      const y = yearSelect.value;
      const m = monthSelect.value;
      const d = daySelect.value;

      if (!y || !m || !d) {
        // не даём отправить, если дата не выбрана полностью
        e.preventDefault();
        return;
      }

      const mm = String(m).padStart(2, "0");
      const dd = String(d).padStart(2, "0");
      dateInput.value = `${y}-${mm}-${dd}`;
    });
  }

  initDateSelectors();

  // ===== ПРОКРУТКА К ЯКОРЮ ПРИ ЗАГРУЗКЕ =====
  // Если в URL есть якорь (например, #message123), прокручиваем к нему
  // Это используется при переходе к дате или к результату поиска
  function scrollToAnchor() {
    if (window.location.hash && window.location.hash.startsWith('#message')) {
      const hash = window.location.hash;
      // Функция для попытки прокрутки
      function attemptScroll() {
        const target = document.querySelector(hash);
        if (target) {
          // Прокручиваем к элементу с центрированием
          target.scrollIntoView({ behavior: 'smooth', block: 'center' });
          // Подсвечиваем найденное сообщение
          target.style.backgroundColor = 'rgba(99, 102, 241, 0.3)';
          target.style.transition = 'background-color 2s ease-out';
          setTimeout(() => {
            target.style.backgroundColor = '';
          }, 2000);
          return true;
        }
        return false;
      }
      
      // Пробуем сразу
      if (!attemptScroll()) {
        // Если не получилось, пробуем через небольшие задержки
        setTimeout(() => {
          if (!attemptScroll()) {
            setTimeout(() => attemptScroll(), 300);
          }
        }, 100);
      }
    }
  }
  
  // Вызываем прокрутку к якорю с задержкой, чтобы DOM успел загрузиться
  // Особенно важно при переходе к дате, когда страница перезагружается
  setTimeout(() => {
    scrollToAnchor();
  }, 500);
  
  // Также слушаем изменения hash (на случай динамической навигации)
  window.addEventListener('hashchange', () => {
    setTimeout(() => scrollToAnchor(), 200);
  });
  
  // Дополнительная попытка после полной загрузки страницы
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(() => scrollToAnchor(), 300);
    });
  }

  // ===== МОДАЛЬНЫЙ ПРОСМОТР МЕДИА (в т.ч. стикеров) =====
  const overlay = document.getElementById("tgmem-media-overlay");
  const overlayContent = document.getElementById("tgmem-media-content");
  const overlayClose = document.getElementById("tgmem-media-close");

  function closeOverlay() {
    if (!overlay || !overlayContent) return;
    overlay.classList.remove("active");
    overlayContent.innerHTML = "";
  }

  if (overlay && overlayClose) {
    overlayClose.addEventListener("click", (e) => {
      e.preventDefault();
      closeOverlay();
    });

    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) {
        closeOverlay();
      }
    });
  }

  function openMediaOverlay(href) {
    if (!overlay || !overlayContent) return;

    overlayContent.innerHTML = "";

    const lower = href.toLowerCase();
    let el;

    const isSticker =
      lower.includes("sticker") || lower.startsWith("stickers/");

    if (isSticker) {
      // Анимированный стикер: маленькое зацикленное видео без контролов
      el = document.createElement("video");
      el.classList.add("tgmem-sticker");
      el.autoplay = true;
      el.loop = true;
      el.muted = true;
      el.src = href;
    } else if (/\.(mp4|mov|mkv|webm)$/.test(lower)) {
      el = document.createElement("video");
      el.controls = true;
      el.autoplay = true;
      el.src = href;
    } else if (/\.(ogg|mp3|wav|m4a)$/.test(lower)) {
      el = document.createElement("audio");
      el.controls = true;
      el.autoplay = true;
      el.src = href;
    } else if (/\.(jpg|jpeg|png|webp|gif)$/.test(lower)) {
      el = document.createElement("img");
      el.src = href;
    } else {
      // fallback — в iframe
      el = document.createElement("iframe");
      el.src = href;
    }

    overlayContent.appendChild(el);
    overlay.classList.add("active");
  }

  if (historyEl) {
    historyEl.addEventListener("click", (e) => {
      const link = e.target.closest("a[href]");
      if (!link) return;

      const href = link.getAttribute("href");
      if (!href) return;
      const lower = href.toLowerCase();

      const isMediaLink =
        lower.startsWith("video_files/") ||
        lower.startsWith("photos/") ||
        lower.startsWith("images/") ||
        lower.startsWith("files/") ||
        lower.startsWith("voice/") ||
        lower.startsWith("audio/") ||
        lower.startsWith("stickers/") ||
        lower.startsWith("round_video_messages/") ||
        /\.(mp4|mov|mkv|webm|ogg|mp3|wav|m4a|jpg|jpeg|png|webp|gif)$/.test(lower);

      if (!isMediaLink) return;

      e.preventDefault();
      openMediaOverlay(href);
    });
  }
});
