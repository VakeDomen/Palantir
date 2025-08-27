pub static DASHBOARD_HTML: &str = r###"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Palantir dashboard</title>
  <script src="https://unpkg.com/htmx.org@1.9.12"></script>
</head>
<body>
  <h2>Dashboard</h2>
  <a href="/admin/logout">Logout</a>
  <form hx-post="/admin/subscribe" hx-target="#subs" hx-swap="outerHTML" style="margin:1rem 0">
    <label>Find assignment
      <input type="text" name="assignment_id" required>
    </label>
    <button type="submit">Subscribe</button>
  </form>

  <div id="subs">
    {% include "subs_list.html" %}
  </div>
</body>
</html>
"###;

pub static SUBS_LIST_HTML: &str = r###"
<h3>Subscribed assignments</h3>
<table border="1" cellpadding="6">
  <tr><th>assignment</th><th>latest status</th><th>count</th><th>actions</th></tr>
  <tbody>
    {% include "subs_rows.html" %}
  </tbody>
</table>
"###;

pub static SUBS_ROWS_HTML: &str = r###"
{% for s in subs %}
<tr>
  <td><a href="/admin/assignment/{{ s.assignment_id }}">{{ s.assignment_id }}</a></td>
  <td>{{ s.latest_status }}</td>
  <td>{{ s.count }}</td>
  <td>
    <form hx-post="/admin/unsubscribe" hx-target="#subs" hx-swap="outerHTML" style="display:inline">
      <input type="hidden" name="assignment_id" value="{{ s.assignment_id }}">
      <button type="submit">Unsubscribe</button>
    </form>
  </td>
</tr>
{% else %}
<tr><td colspan="4">No subscriptions yet</td></tr>
{% endfor %}
"###;

pub static ASSIGN_ROWS_HTML: &str = r###"
{% for r in rows %}
<tr>
  <td>{{ r.id }}</td>
  <td>{{ r.student_name }}</td>
  <td>{{ r.created_at }}</td>
  <td>{{ r.status }}</td>
  <td><a href="/admin/submissions/{{ r.id }}">open</a></td>
</tr>
{% else %}
<tr><td colspan="5">No submissions for this assignment</td></tr>
{% endfor %}
"###;
