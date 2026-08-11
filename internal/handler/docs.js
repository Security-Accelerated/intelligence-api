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

/* Copy button on every code block.

   Injected here rather than written into the four HTML files by hand, for the
   same reason the table wrappers are detected here: the blocks are edited
   often and a control that has to be remembered per block will be missed.

   The button is placed in a wrapper around the <pre>, not inside it. A <pre> is
   its own horizontal scroll container, so a control positioned inside one
   slides away with the code as soon as the reader scrolls sideways — which on
   these pages is exactly when a 40-line payload is hardest to select by hand.

   No clipboard API means no button: on an insecure origin the copy would fail
   every time, and a control that cannot work is worse than the plain
   selectable block the reader already has. */
(function() {
  var main = document.querySelector('main');
  if (!main) return;
  if (!navigator.clipboard || !navigator.clipboard.writeText) return;

  var blocks = main.querySelectorAll('pre');
  if (!blocks.length) return;

  /* The nearest heading above the block, used to give each button a distinct
     accessible name — twenty-seven buttons all called "Copy" is a tab order
     that tells a screen reader nothing. */
  function sectionTitle(el) {
    var node = el;
    while (node && node !== main.parentElement) {
      var sib = node.previousElementSibling;
      while (sib) {
        if (/^H[1-6]$/.test(sib.tagName)) return sib.textContent.trim();
        var nested = sib.querySelectorAll('h1, h2, h3, h4, h5, h6');
        if (nested.length) return nested[nested.length - 1].textContent.trim();
        sib = sib.previousElementSibling;
      }
      node = node.parentElement;
    }
    return '';
  }

  function selectContents(el) {
    try {
      var range = document.createRange();
      range.selectNodeContents(el);
      var selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    } catch (err) {}
  }

  blocks.forEach(function(pre) {
    var code = pre.querySelector('code') || pre;

    var wrapper = document.createElement('div');
    wrapper.className = 'code-block';
    pre.parentNode.insertBefore(wrapper, pre);
    wrapper.appendChild(pre);

    var label = document.createElement('span');
    label.className = 'code-copy-label';
    label.textContent = 'Copy';

    var context = sectionTitle(wrapper);
    var suffix = document.createElement('span');
    suffix.className = 'visually-hidden';
    suffix.textContent = context ? ' code: ' + context : ' code';

    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'code-copy';
    button.appendChild(label);
    button.appendChild(suffix);

    /* Announced separately: a screen reader does not reliably re-read the
       accessible name of the button the user just activated. */
    var status = document.createElement('span');
    status.className = 'visually-hidden';
    status.setAttribute('role', 'status');

    wrapper.appendChild(button);
    wrapper.appendChild(status);

    var reset = null;
    function report(text, announce, copied) {
      label.textContent = text;
      status.textContent = announce;
      /* The confirming colour is for a copy that happened, not for the
         fallback — a green "Selected" would read as success. */
      button.classList.toggle('is-copied', copied);
      clearTimeout(reset);
      reset = setTimeout(function() {
        label.textContent = 'Copy';
        status.textContent = '';
        button.classList.remove('is-copied');
      }, 1800);
    }

    button.addEventListener('click', function() {
      /* textContent, not the markup: the blocks carry <span class="str"> and
         friends for syntax colour, and the reader wants the code. */
      navigator.clipboard.writeText(code.textContent).then(function() {
        report('Copied', 'Copied to clipboard', true);
      }, function() {
        /* Denied permission or a browser that rejects the write. Selecting the
           block leaves the reader something to act on rather than an error
           they can do nothing about. */
        selectContents(code);
        report('Selected', 'Copy was blocked. The code is selected — copy it with your keyboard.', false);
      });
    });
  });
})();

/* Search over the page's own headings and table rows.

   The reference pages run to fourteen lookups and forty-odd tables, and the
   browser's own find is a weak tool on them: `cache_hit` is a field on every
   lookup, so find walks fourteen identical hits with no way to tell which
   lookup each belongs to. Every result here carries the section it sits in.

   The index is built from the rendered DOM, so it cannot drift from the page,
   and the whole feature is injected: with JavaScript off there is no search
   box promising something that will not happen — the page stays the readable
   static HTML it already is. */
(function() {
  var main = document.querySelector('main');
  if (!main) return;

  var actions = document.querySelector('.topbar-actions');
  if (!actions) return;

  var SVG_NS = 'http://www.w3.org/2000/svg';

  function magnifier() {
    var svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    var circle = document.createElementNS(SVG_NS, 'circle');
    circle.setAttribute('cx', '11');
    circle.setAttribute('cy', '11');
    circle.setAttribute('r', '6.4');
    circle.setAttribute('fill', 'none');
    circle.setAttribute('stroke', 'currentColor');
    circle.setAttribute('stroke-width', '1.8');
    var handle = document.createElementNS(SVG_NS, 'path');
    handle.setAttribute('d', 'M15.8 15.8 20 20');
    handle.setAttribute('stroke', 'currentColor');
    handle.setAttribute('stroke-width', '1.8');
    handle.setAttribute('stroke-linecap', 'round');
    svg.appendChild(circle);
    svg.appendChild(handle);
    return svg;
  }

  function clean(text) {
    return text.replace(/\s+/g, ' ').trim();
  }

  /* --- Index ---------------------------------------------------------- */

  var entries = [];
  /* No prototype: the keys are page text, and a field named "constructor"
     should not read as already seen. */
  var seen = Object.create(null);
  var trail = [];

  main.querySelectorAll('h2, h3, h4, table tbody tr').forEach(function(node) {
    /* Anything not rendered — the inactive halves of the language tabs — is
       skipped: jumping to it would scroll to nothing. */
    if (!node.getClientRects().length) return;

    if (node.tagName === 'TR') {
      var cell = node.querySelector('td');
      if (!cell) return;
      var field = clean(cell.textContent);
      /* A first cell that is a sentence is prose, not a field name. */
      if (!field || field.length > 60) return;
      add(field, trail.slice(), node, 'field');
      return;
    }

    var level = parseInt(node.tagName.slice(1), 10);
    trail = trail.filter(function(item) { return item.level < level; });
    var title = clean(node.textContent);
    if (!title) return;
    var name = headingName(title);
    trail.push({ level: level, title: name });
    add(name, trail.slice(0, -1), node, 'section', title);
  });

  /* The response-field headings read "ssl -- TLS Certificate". Indexing the
     whole line means a search for "ssl" matches the heading no better than it
     matches a table row that happens to mention it, and the lookup the reader
     asked for ranks below the row. The name is the part before the dash. */
  function headingName(title) {
    var split = title.split(/\s[-–—]{1,2}\s/);
    if (split.length > 1 && split[0].length <= 40) return split[0].trim();
    return title;
  }

  function add(label, path, el, kind, detail) {
    var context = path.map(function(item) { return item.title; });
    /* Only the two closest levels are shown: the full path on a response-field
       table reads "Response Fields > ssl > Certificate", where the lookup name
       is the part that disambiguates and the page title is not. */
    var scope = context.slice(-2).join(' › ');
    var key = kind + ' ' + label + ' ' + scope;
    if (seen[key]) return;
    seen[key] = true;
    entries.push({
      label: label,
      scope: scope,
      full: context.concat([detail || label]).join(' › '),
      kind: kind,
      el: el,
      /* The heading's description stays searchable even though it is no longer
         the label: "TLS Certificate" should still find the ssl section. */
      haystack: (label + ' ' + (detail || '') + ' ' + context.join(' ')).toLowerCase(),
      lower: label.toLowerCase()
    });
  }

  /* A page with almost nothing to index — the 404 — gets no search control. */
  if (entries.length < 4) return;

  /* --- Matching ------------------------------------------------------- */

  var LIMIT = 30;

  function rank(entry, query, tokens) {
    for (var i = 0; i < tokens.length; i++) {
      if (entry.haystack.indexOf(tokens[i]) === -1) return -1;
    }
    if (entry.lower === query) return 0;
    if (entry.lower.indexOf(query) === 0) return 1;
    if (entry.lower.indexOf(query) !== -1) return 2;
    return 3;
  }

  function search(raw) {
    var query = clean(raw).toLowerCase();
    if (!query) return [];
    var tokens = query.split(' ');
    var hits = [];
    entries.forEach(function(entry) {
      var score = rank(entry, query, tokens);
      if (score < 0) return;
      hits.push({ entry: entry, score: score });
    });
    hits.sort(function(a, b) {
      if (a.score !== b.score) return a.score - b.score;
      /* A section heading outranks a field of the same name: "ssl" should
         offer the lookup before the row that mentions it. */
      if (a.entry.kind !== b.entry.kind) return a.entry.kind === 'section' ? -1 : 1;
      return a.entry.label.length - b.entry.label.length;
    });
    return hits.map(function(hit) { return hit.entry; });
  }

  /* --- Overlay -------------------------------------------------------- */

  var trigger = document.createElement('button');
  trigger.type = 'button';
  trigger.className = 'docs-search-trigger';
  trigger.setAttribute('aria-label', 'Search this page');
  trigger.setAttribute('title', 'Search this page (press /)');
  trigger.setAttribute('aria-keyshortcuts', '/ Meta+K Control+K');
  trigger.appendChild(magnifier());
  var themeToggle = actions.querySelector('[data-theme-toggle]');
  if (themeToggle && themeToggle.parentElement === actions) {
    actions.insertBefore(trigger, themeToggle);
  } else {
    actions.appendChild(trigger);
  }

  var overlay = document.createElement('div');
  overlay.className = 'docs-search';
  overlay.hidden = true;

  var backdrop = document.createElement('div');
  backdrop.className = 'docs-search-backdrop';

  var panel = document.createElement('div');
  panel.className = 'docs-search-panel';
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-modal', 'true');
  panel.setAttribute('aria-label', 'Search this page');

  var field = document.createElement('div');
  field.className = 'docs-search-field';
  field.appendChild(magnifier());

  var input = document.createElement('input');
  input.type = 'text';
  input.className = 'docs-search-input';
  input.placeholder = 'Search fields and sections';
  input.setAttribute('role', 'combobox');
  input.setAttribute('aria-expanded', 'false');
  input.setAttribute('aria-controls', 'docs-search-results');
  input.setAttribute('aria-autocomplete', 'list');
  input.setAttribute('aria-label', 'Search this page');
  input.autocomplete = 'off';
  input.spellcheck = false;
  field.appendChild(input);

  var list = document.createElement('ul');
  list.className = 'docs-search-results';
  list.id = 'docs-search-results';
  list.setAttribute('role', 'listbox');
  list.setAttribute('aria-label', 'Search results');

  var status = document.createElement('p');
  status.className = 'docs-search-status';
  status.setAttribute('role', 'status');

  var hint = document.createElement('p');
  hint.className = 'docs-search-hint';
  hint.textContent = '↑↓ to move · ↵ to jump · esc to close';

  panel.appendChild(field);
  panel.appendChild(list);
  panel.appendChild(status);
  panel.appendChild(hint);
  overlay.appendChild(backdrop);
  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  var results = [];
  var active = -1;
  var restoreFocus = null;

  function reduceMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function render(hits) {
    results = hits;
    active = hits.length ? 0 : -1;
    list.textContent = '';

    hits.forEach(function(entry, index) {
      var item = document.createElement('li');
      item.className = 'docs-search-result';
      item.id = 'docs-search-result-' + index;
      item.setAttribute('role', 'option');
      item.setAttribute('aria-selected', index === 0 ? 'true' : 'false');
      if (entry.full) item.title = entry.full;

      var name = document.createElement('span');
      name.className = 'docs-search-result-label';
      name.textContent = entry.label;
      item.appendChild(name);

      if (entry.scope) {
        var scope = document.createElement('span');
        scope.className = 'docs-search-result-scope';
        scope.textContent = entry.scope;
        item.appendChild(scope);
      }

      /* mousedown, not click: the input must not lose focus first. */
      item.addEventListener('mousedown', function(event) {
        event.preventDefault();
        jump(entry);
      });
      list.appendChild(item);
    });

    input.setAttribute('aria-expanded', hits.length ? 'true' : 'false');
    syncActive();
  }

  function syncActive() {
    var items = list.children;
    for (var i = 0; i < items.length; i++) {
      var selected = i === active;
      items[i].setAttribute('aria-selected', selected ? 'true' : 'false');
      items[i].classList.toggle('is-active', selected);
      if (selected) items[i].scrollIntoView({ block: 'nearest' });
    }
    input.setAttribute('aria-activedescendant', active >= 0 ? 'docs-search-result-' + active : '');
  }

  function move(delta) {
    if (!results.length) return;
    active = (active + delta + results.length) % results.length;
    syncActive();
  }

  function update() {
    var query = input.value;
    var matches = search(query);
    /* The count is of everything that matched, and the list is the top slice of
       it: a reader told "30 matches" when there were 200 would stop refining a
       query that has not narrowed anything. */
    render(matches.slice(0, LIMIT));

    if (!clean(query)) {
      status.textContent = '';
    } else if (!matches.length) {
      status.textContent = 'No matches on this page.';
    } else {
      status.textContent = matches.length + (matches.length === 1 ? ' match' : ' matches') +
        (matches.length > LIMIT ? ' (showing the closest ' + LIMIT + ')' : '');
    }
  }

  function open() {
    if (!overlay.hidden) return;
    restoreFocus = document.activeElement;

    /* The drawer is closed rather than left open underneath, and the overlay
       takes its own scroll lock: body.shell-open is what slides the drawer
       out, so reusing it here would open the drawer behind the overlay on a
       phone. */
    var sidebar = document.querySelector('.sidebar');
    if (sidebar) sidebar.classList.remove('open');
    document.body.classList.remove('shell-open');

    overlay.hidden = false;
    document.body.classList.add('search-open');
    input.select();
    input.focus();
    update();
  }

  function close() {
    if (overlay.hidden) return;
    overlay.hidden = true;
    document.body.classList.remove('search-open');
    if (restoreFocus && restoreFocus.focus) restoreFocus.focus();
    restoreFocus = null;
  }

  var lastHit = null;

  function jump(entry) {
    close();

    var offset = 24;
    var bar = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--topbar-height'));
    if (!isNaN(bar)) offset += bar;

    var top = entry.el.getBoundingClientRect().top + window.pageYOffset - offset;
    window.scrollTo({ top: Math.max(top, 0), behavior: reduceMotion() ? 'auto' : 'smooth' });

    if (lastHit) lastHit.classList.remove('is-search-hit');
    entry.el.classList.add('is-search-hit');
    lastHit = entry.el;
    setTimeout(function() {
      if (lastHit === entry.el) {
        entry.el.classList.remove('is-search-hit');
        lastHit = null;
      }
    }, 2400);

    /* Focus follows the jump so a keyboard reader carries on from the result
       rather than from the top of the document. */
    entry.el.setAttribute('tabindex', '-1');
    try {
      entry.el.focus({ preventScroll: true });
    } catch (err) {
      entry.el.focus();
    }
  }

  trigger.addEventListener('click', open);
  backdrop.addEventListener('click', close);
  input.addEventListener('input', update);

  /* The input is the only focusable control in the dialog — the results are
     driven by the arrow keys, not by the tab order — so Tab has nowhere to go
     inside it and would otherwise walk into the page behind, which
     aria-modal says is not there. */
  panel.addEventListener('keydown', function(event) {
    if (event.key !== 'Tab') return;
    event.preventDefault();
    input.focus();
  });

  input.addEventListener('keydown', function(event) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      move(1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      move(-1);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      if (active >= 0) jump(results[active]);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      close();
    }
  });

  function typingElsewhere(target) {
    if (!target) return false;
    if (target.isContentEditable) return true;
    return /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName);
  }

  document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape' && !overlay.hidden) {
      close();
      return;
    }
    if (event.defaultPrevented || event.altKey) return;

    var isSlash = event.key === '/' && !event.metaKey && !event.ctrlKey;
    var isCommandK = (event.key === 'k' || event.key === 'K') && (event.metaKey || event.ctrlKey);
    if (!isSlash && !isCommandK) return;
    if (typingElsewhere(event.target)) return;

    event.preventDefault();
    open();
  });
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
