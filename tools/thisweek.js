/* Brightspace "this week" export for the Home Hub School tab.
 *
 * HOW TO USE
 *   1. Sign in to your school's Brightspace (https://<your-school>.brightspace.com) and open any page.
 *   2. F12 -> Console -> paste this whole file -> Enter.
 *   3. Run:  await thisweek()                // prints a report and downloads schedule.json
 *      or:   await thisweek({days: 90})      // look further ahead (default 45)
 *      or:   await thisweek({back: 14})      // and further back (default 7)
 *      or:   await thisweek({markdown:true}) // also download THISWEEK.md
 *      or:   await thisweek({download:false})
 *   4. Home Hub -> School -> Import (the upload icon) and pick schedule.json.
 *
 * Read-only: only issues GETs, authenticated by the session cookie of the tab
 * you are already signed in on. No credentials are read, typed or stored.
 * Courses are discovered from your enrollments, so new ones appear automatically.
 *
 * LE/LP are Brightspace API versions; if a call 404s, see /d2l/api/versions/ on
 * your instance. TZ is the time zone the report is written in.
 */
(() => {
  const LE = '1.99';
  const LP = '1.43';
  const TZ = 'America/New_York';

  const get = async (p) => {
    try {
      const r = await fetch(p, { credentials: 'same-origin' });
      return r.ok ? await r.json() : null;
    } catch (e) { return null; }
  };
  // Endpoints disagree on shape: bare array, {Objects:[...]} or {Items:[...]}.
  const arr = (v) => (Array.isArray(v) ? v : (v && (v.Objects || v.Items)) || []);
  const norm = (s) => (s || '').toLowerCase().replace(/[^a-z0-9.]+/g, ' ').trim();
  const shortName = (n) => (n.match(/\b([A-Z]{3,4}\d{3})\b/) || [])[1] || n;

  const fmt = (d) => d.toLocaleString('en-US', {
    timeZone: TZ, weekday: 'short', month: 'short', day: '2-digit', hour: 'numeric', minute: '2-digit',
  });
  // Naive values ("2026-10-05T00:00:00.000", no Z) are already local; real ISO ones are UTC.
  const parse = (s) => {
    if (!s) return null;
    if (/(Z|[+-]\d\d:?\d\d)$/.test(s)) return new Date(s);
    const [y, m, d, hh = 0, mm = 0] = s.match(/\d+/g).map(Number);
    // Interpret as America/New_York wall time.
    const guess = new Date(Date.UTC(y, m - 1, d, hh, mm));
    const off = new Date(guess.toLocaleString('en-US', { timeZone: TZ })) - new Date(guess.toLocaleString('en-US', { timeZone: 'UTC' }));
    return new Date(guess.getTime() - off);
  };

  window.thisweek = async (opts = {}) => {
    const days = opts.days || 45;
    const back = opts.back ?? 7;   // also export the last week, so the calendar shows what was due
    const now = new Date();
    const dayStart = new Date(now.toLocaleDateString('en-US', { timeZone: TZ }) + ' 00:00');
    const from = new Date(dayStart.getTime() - back * 864e5);
    const end = new Date(dayStart.getTime() + days * 864e5);
    // Everything up to the coming Sunday night counts as "this week".
    const dow = new Date(now.toLocaleString('en-US', { timeZone: TZ })).getDay();
    const weekEnd = new Date(dayStart.getTime() + ((7 - dow) % 7 + 1) * 864e5);

    const enr = arr(await get(`/d2l/api/lp/${LP}/enrollments/myenrollments/?pageSize=100`));
    const courses = enr
      .filter((e) => e.OrgUnit && e.OrgUnit.Type && e.OrgUnit.Type.Code === 'Course Offering')
      .map((e) => ({ ou: e.OrgUnit.Id, name: shortName(e.OrgUnit.Name), full: e.OrgUnit.Name }));

    const items = [], news = [], notes = [], scored = [];
    for (const c of courses) {
      const base = `/d2l/api/le/${LE}/${c.ou}`;
      const [cal, dz, qz, gi, gv, nw] = await Promise.all([
        get(`${base}/calendar/events/myEvents/?startDateTime=${from.toISOString()}&endDateTime=${end.toISOString()}`),
        get(`${base}/dropbox/folders/`), get(`${base}/quizzes/`),
        get(`${base}/grades/`), get(`${base}/grades/values/myGradeValues/`),
        get(`${base}/news/`),
      ]);
      if (!cal && !dz && !qz) { notes.push(`${c.name}: no access (course not published yet?)`); continue; }

      // A grade item counts as done once it has a score.
      const gname = {}; arr(gi).forEach((g) => { gname[g.Id] = norm(g.Name); });
      const done = new Set(arr(gv).filter((v) => v.PointsNumerator != null).map((v) => gname[v.GradeObjectIdentifier]));
      // Every scored grade item, whatever its date, so the Hub can tick off calendar-feed events too.
      arr(gv).filter((v) => v.PointsNumerator != null && v.GradeObjectName).forEach((v) => scored.push(v.GradeObjectName));
      const isDone = (t) => { const n = norm(t); return [...done].some((d) => d && (d === n || d.includes(n) || n.includes(d))); };

      const seen = new Set();
      const add = (kind, title, when) => {
        if (!when || when < from || when > end) return;
        const key = `${norm(title)}|${when.getTime()}`;
        if (seen.has(key)) return; seen.add(key);
        items.push({ course: c.name, kind, title, when, done: isDone(title) });
      };
      arr(cal).forEach((e) => add('Calendar', e.Title, parse(e.StartDateTime || e.StartDay || e.EndDateTime)));
      arr(dz).forEach((f) => add('Assignment', f.Name, parse(f.DueDate)));
      arr(qz).forEach((q) => add('Quiz', q.Name, parse(q.DueDate)));

      const noDue = arr(dz).filter((f) => !f.DueDate).length;
      if (noDue) notes.push(`${c.name}: ${noDue} assignment(s) have no due date in Brightspace - check the syllabus/schedule or ask the instructor.`);

      arr(nw).filter((n) => parse(n.StartDate) > new Date(now - 14 * 864e5)).slice(0, 3)
        .forEach((n) => news.push({ course: c.name, when: parse(n.StartDate), title: n.Title, body: ((n.Body && n.Body.Text) || '').trim() }));
    }

    items.sort((a, b) => a.when - b.when);
    const row = (i) => `- [${i.done ? 'x' : ' '}] **${fmt(i.when)}** - ${i.course} - ${i.title}${i.kind === 'Calendar' ? '' : ` _(${i.kind})_`}`;
    const todo = items.filter((i) => !i.done && i.when >= dayStart);
    // weekEnd is Monday 00:00, so all-day Monday items belong to next week.
    const thisW = todo.filter((i) => i.when < weekEnd), later = todo.filter((i) => i.when >= weekEnd);
    const md = [
      `# This week - generated ${fmt(now)} (${TZ})`,
      '',
      `## Due by Sunday night (${thisW.length})`, ...(thisW.length ? thisW.map(row) : ['_Nothing._']),
      '', `## Coming up, next ${days} days (${later.length})`, ...(later.length ? later.map(row) : ['_Nothing._']),
      '', `## Already scored (${items.length - todo.length})`, ...items.filter((i) => i.done).map(row),
      '', '## Recent announcements',
      ...(news.length ? news.map((n) => `- **${n.course}** (${fmt(n.when)}) ${n.title}\n  > ${n.body.replace(/\s+/g, ' ').slice(0, 400)}`) : ['_None in the last 14 days._']),
      '', '## Caveats', ...(notes.length ? notes.map((n) => `- ${n}`) : []),
      '- "Already scored" means the matching grade item has a score; a submission that is not yet graded still shows as open.',
      '- Items are matched by title, so double-check anything that looks wrong.',
    ].join('\n');

    // schedule.json is what the Home Hub's School tab imports.
    const data = {
      generated: now.toISOString(), tz: TZ,
      items: items.map((i) => ({ course: i.course, kind: i.kind, title: i.title, when: i.when.toISOString(), done: i.done })),
      news: news.map((n) => ({ course: n.course, when: n.when.toISOString(), title: n.title, body: n.body.replace(/\s+/g, ' ').slice(0, 400) })),
      notes,
      scored,
    };

    console.log(md);
    const save = (text, type, name) => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type }));
      a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
    };
    if (opts.download !== false) {
      save(JSON.stringify(data, null, 1), 'application/json', 'schedule.json');
      if (opts.markdown) save(md, 'text/markdown', 'THISWEEK.md');
    }
    return data;
  };
  console.log('thisweek() ready - run: await thisweek()');
})();
