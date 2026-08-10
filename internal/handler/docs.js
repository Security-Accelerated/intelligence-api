/* Shared behavior for the docs pages (/docs, /docs/domain, /docs/ip).
   Each feature guards against missing elements, since not every page has
   language tabs, a sidebar, or a theme toggle. */

/* Language tab switching */
document.querySelectorAll('.lang-tab').forEach(function(tab) {
  tab.addEventListener('click', function() {
    var lang = tab.getAttribute('data-lang');
    if (!lang) return;

    var tabs = tab.parentElement.querySelectorAll('.lang-tab');
    tabs.forEach(function(t) { t.classList.remove('active'); });
    tab.classList.add('active');

    var container = tab.parentElement.parentElement;
    container.querySelectorAll('.lang-panel').forEach(function(p) { p.classList.remove('active'); });
    var panel = container.querySelector('#tab-' + lang);
    if (panel) panel.classList.add('active');
  });
});

/* Sidebar open/close (mobile) */
(function() {
  var sidebar = document.querySelector('.sidebar');
  if (!sidebar) return;

  function closeSidebar() {
    sidebar.classList.remove('open');
    document.body.classList.remove('shell-open');
  }

  function toggleSidebar() {
    var isOpen = sidebar.classList.toggle('open');
    document.body.classList.toggle('shell-open', isOpen);
  }

  var toggle = document.querySelector('[data-sidebar-toggle]');
  if (toggle) toggle.addEventListener('click', toggleSidebar);

  var backdrop = document.querySelector('[data-sidebar-close]');
  if (backdrop) backdrop.addEventListener('click', closeSidebar);

  document.querySelectorAll('.sidebar a').forEach(function(link) {
    link.addEventListener('click', function() {
      if (window.innerWidth <= 860) {
        closeSidebar();
      }
    });
  });

  window.addEventListener('resize', function() {
    if (window.innerWidth > 860) {
      closeSidebar();
    }
  });
})();

/* Theme toggle */
(function() {
  var storageKey = "sa-docs-theme";
  var root = document.documentElement;
  var toggle = document.querySelector('[data-theme-toggle]');
  if (!toggle) return;

  var label = toggle.querySelector('.theme-toggle-label');

  function setTheme(theme) {
    var nextTheme = theme === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', theme);
    root.style.colorScheme = theme;
    toggle.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
    toggle.setAttribute('aria-label', 'Theme: ' + theme + ' mode. Activate to switch to ' + nextTheme + ' mode.');
    toggle.setAttribute('title', 'Switch to ' + nextTheme + ' mode');
    label.textContent = theme === 'dark' ? 'Dark mode' : 'Light mode';
  }

  function storedTheme() {
    try {
      return localStorage.getItem(storageKey);
    } catch (err) {
      return null;
    }
  }

  setTheme(root.getAttribute('data-theme') || 'light');

  toggle.addEventListener('click', function() {
    var nextTheme = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    try {
      localStorage.setItem(storageKey, nextTheme);
    } catch (err) {}
  });

  if (!window.matchMedia) return;
  var media = window.matchMedia('(prefers-color-scheme: dark)');
  var syncTheme = function(event) {
    var savedTheme = storedTheme();
    if (savedTheme === 'light' || savedTheme === 'dark') return;
    setTheme(event.matches ? 'dark' : 'light');
  };

  if (media.addEventListener) {
    media.addEventListener('change', syncTheme);
  } else if (media.addListener) {
    media.addListener(syncTheme);
  }
})();

/* Keyboard access for tables that scroll sideways.

   A scrollable box is only reachable by keyboard if it is focusable, but
   marking every table focusable in the markup would add a dead tab stop for
   each of the ~40 tables on the domain page that fit fine. So the tab stop is
   granted only while a table actually overflows, which on these pages means
   only on narrow viewports. */
(function() {
  var wrappers = document.querySelectorAll('.table-scroll');
  if (!wrappers.length) return;

  function sync() {
    wrappers.forEach(function(el) {
      if (el.scrollWidth > el.clientWidth + 1) {
        el.classList.add('is-scrollable');
        el.setAttribute('tabindex', '0');
        el.setAttribute('role', 'region');
        el.setAttribute('aria-label', 'Table, scrollable');
      } else {
        el.classList.remove('is-scrollable');
        el.removeAttribute('tabindex');
        el.removeAttribute('role');
        el.removeAttribute('aria-label');
      }
    });
  }

  sync();
  window.addEventListener('resize', sync);
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(sync);
  }
})();

/* Sidebar scroll-spy */
(function() {
  var links = document.querySelectorAll('.sidebar a[href^="#"]');
  if (!links.length) return;

  var sections = [];
  links.forEach(function(link) {
    var id = link.getAttribute('href').slice(1);
    var el = document.getElementById(id);
    if (el) sections.push({ el: el, link: link });
  });

  function onScroll() {
    var scrollY = window.scrollY + 140;
    var active = null;
    for (var i = sections.length - 1; i >= 0; i--) {
      if (sections[i].el.offsetTop <= scrollY) {
        active = sections[i];
        break;
      }
    }
    links.forEach(function(l) { l.classList.remove('active'); });
    if (active) active.link.classList.add('active');
  }

  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
})();
