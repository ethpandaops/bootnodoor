/* Shared column sorting + status filtering for the node tables
   (el-nodes, cl-nodes, nodes). Must be loaded after knockout.min.js.

   Works in two phases:
   - before Knockout binds (first ~20s, server-rendered rows): rows are
     sorted/filtered directly in the DOM using the cell contents
   - after Knockout binds: the page view model's `visibleNodes` computed
     calls transform(), so every AJAX refresh keeps the sort/filter */
window.NodeTable = (function () {
  var sortKey = ko.observable(null);
  var sortDir = ko.observable(1); /* 1 = asc, -1 = desc */
  var filter = ko.observable('all'); /* all | alive | dead */
  var bound = false;
  var table = null;
  var filterBar = null;
  var afterUpdate = null;

  /* "10.2.3.4:30303" -> "010.002.003.004:30303" so lexicographic order
     matches numeric order; non-IPv4 addresses fall through as-is */
  function ipSortKey(ipPort) {
    var idx = ipPort.lastIndexOf(':');
    var ip = idx >= 0 ? ipPort.slice(0, idx) : ipPort;
    var port = idx >= 0 ? ipPort.slice(idx + 1) : '';
    var m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (m) {
      ip = m.slice(1).map(function (o) { return ('000' + o).slice(-3); }).join('.');
    }
    return ip + ':' + ('00000' + port).slice(-5);
  }

  /* How to read each sortable column from a NodeViewModel */
  var getters = {
    peerid:   function (n) { return String(n.PeerID).toLowerCase(); },
    ip:       function (n) { return ipSortKey(n.IP + ':' + n.Port); },
    fork:     function (n) { return String(n.ForkDigest || '').toLowerCase(); },
    protocol: function (n) { return String(n.ProtocolSupport || '').toLowerCase(); },
    enrseq:   function (n) { return Number(n.ENRSeq) || 0; },
    first:    function (n) { return n.FirstSeenTimestamp || 0; },
    last:     function (n) { return n.LastSeenTimestamp || 0; },
    success:  function (n) { return Number(n.SuccessCount) || 0; },
    failures: function (n) { return Number(n.FailureCount) || 0; },
    rtt:      function (n) { return n.AvgRTT > 0 ? n.AvgRTT : Infinity; },
    score:    function (n) { return Number(n.Score) || 0; },
    alive:    function (n) { return n.IsAlive ? 1 : 0; }
  };

  function compare(a, b) {
    if (typeof a === 'number' && typeof b === 'number') {
      if (a === b) return 0;
      return a < b ? -1 : 1;
    }
    return String(a).localeCompare(String(b));
  }

  /* Filter + sort a NodeViewModel array; registers Knockout dependencies
     so computeds using it re-evaluate when the sort/filter changes */
  function transform(nodes) {
    var f = filter();
    var key = sortKey();
    var dir = sortDir();
    var out = nodes;
    if (f === 'alive') {
      out = out.filter(function (n) { return n.IsAlive; });
    } else if (f === 'dead') {
      out = out.filter(function (n) { return !n.IsAlive; });
    }
    if (key && getters[key]) {
      var get = getters[key];
      out = out.slice().sort(function (a, b) { return compare(get(a), get(b)) * dir; });
    }
    return out;
  }

  /* --- DOM fallback used before Knockout takes over the table --- */

  function serverRows(tbody) {
    return Array.prototype.filter.call(tbody.querySelectorAll('tr'), function (tr) {
      return !tr.classList.contains('template-row');
    });
  }

  function cellSortValue(row, cellIndex, type) {
    var cell = row.cells[cellIndex];
    if (!cell) return '';
    var text = cell.textContent.trim();
    if (type === 'time') {
      var el = cell.querySelector('[data-timer]');
      return el ? (parseInt(el.getAttribute('data-timer'), 10) || 0) : 0;
    }
    if (type === 'num') {
      var n = parseFloat(text);
      return isNaN(n) ? Infinity : n;
    }
    if (type === 'ip') return ipSortKey(text);
    if (type === 'alive') return text === 'Alive' ? 1 : 0;
    return text.toLowerCase();
  }

  function applyDom() {
    var tbody = table.tBodies[0];
    if (!tbody) return;
    var rows = serverRows(tbody);

    var f = filter();
    var aliveTh = table.querySelector('th[data-sort="alive"]');
    rows.forEach(function (row) {
      var hide = false;
      if (f !== 'all' && aliveTh) {
        var alive = cellSortValue(row, aliveTh.cellIndex, 'alive') === 1;
        hide = (f === 'alive' && !alive) || (f === 'dead' && alive);
      }
      row.style.display = hide ? 'none' : '';
    });

    var key = sortKey();
    if (!key) return;
    var th = table.querySelector('th[data-sort="' + key + '"]');
    if (!th) return;
    var type = th.getAttribute('data-sort-type') || 'text';
    var dir = sortDir();
    rows
      .map(function (row) { return { row: row, val: cellSortValue(row, th.cellIndex, type) }; })
      .sort(function (a, b) { return compare(a.val, b.val) * dir; })
      .forEach(function (item) { tbody.appendChild(item.row); });
  }

  function updateIndicators() {
    if (!table) return;
    Array.prototype.forEach.call(table.querySelectorAll('th[data-sort]'), function (th) {
      th.classList.remove('sort-asc', 'sort-desc');
      if (th.getAttribute('data-sort') === sortKey()) {
        th.classList.add(sortDir() === 1 ? 'sort-asc' : 'sort-desc');
      }
    });
    if (filterBar) {
      Array.prototype.forEach.call(filterBar.querySelectorAll('[data-filter]'), function (el) {
        var f = el.getAttribute('data-filter');
        el.classList.toggle('active', f === filter() && f !== 'all');
      });
    }
  }

  function refresh() {
    updateIndicators();
    if (bound) {
      /* Knockout re-renders the rows via transform(); re-init tooltips */
      if (afterUpdate) setTimeout(afterUpdate, 50);
    } else {
      applyDom();
    }
  }

  function setSort(key) {
    if (sortKey() === key) {
      sortDir(-sortDir());
    } else {
      sortDir(1);
      sortKey(key);
    }
    refresh();
  }

  function setFilter(f) {
    filter(filter() === f ? 'all' : f);
    refresh();
  }

  function init(opts) {
    table = opts.table;
    filterBar = opts.filterBar || null;
    afterUpdate = opts.afterUpdate || null;
    if (table) {
      table.tHead.addEventListener('click', function (e) {
        var th = e.target.closest('th[data-sort]');
        if (th) setSort(th.getAttribute('data-sort'));
      });
    }
    if (filterBar) {
      filterBar.addEventListener('click', function (e) {
        var el = e.target.closest('[data-filter]');
        if (el) setFilter(el.getAttribute('data-filter'));
      });
    }
  }

  function markBound() {
    bound = true;
  }

  return {
    init: init,
    markBound: markBound,
    transform: transform
  };
})();
