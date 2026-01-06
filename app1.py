# app_sqlserver.py

import streamlit as st
import pandas as pd
import pyodbc
import socket
import psutil
from io import BytesIO

# ---------- Optional autorefresh ----------
try:
    from streamlit_autorefresh import st_autorefresh
    AUTORF_AVAILABLE = True
except Exception:
    AUTORF_AVAILABLE = False

# ---------- Optional ping3; fallback to system ping ----------
PING3_AVAILABLE = False
try:
    from ping3 import ping as ping3_ping
    PING3_AVAILABLE = True
except Exception:
    import subprocess

    def _sys_ping_once(host: str, timeout_sec: float = 1.5) -> bool:
        try:
            ms = str(int(timeout_sec * 1000))
            result = subprocess.run(
                ["ping", "-n", "1", "-w", ms, host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return result.returncode == 0
        except Exception:
            return False

# =========================
# CONFIG
# =========================
DB_SERVER = r"DESKTOP-A3SK9UM\SQLEXPRESS"   # <-- set your SQL Server instance
DB_NAME   = "Retail"

PUBLIC_PING_HOST_DEFAULT = "8.8.8.8"
RETAIL_SERVER_HOST_DEFAULT = "localhost"

st.set_page_config(page_title="Retail Operations Optimization System",
                   layout="wide",
                   page_icon="🛠️")

# =========================
# UTILS
# =========================
def rerun():
    try:
        st.rerun()
    except Exception:
        st.experimental_rerun()

def db_conn():
    # Windows Authentication; ODBC Driver 18. Adjust if using SQL auth.
    return pyodbc.connect(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        f"SERVER={DB_SERVER};"
        f"DATABASE={DB_NAME};"
        "Trusted_Connection=yes;"
        "Encrypt=yes;"
        "TrustServerCertificate=yes;"
    )

def q_df(query: str, params=None) -> pd.DataFrame:
    conn = db_conn()
    try:
        return pd.read_sql(query, conn, params=params)
    finally:
        conn.close()

def q_exec(query: str, params=None, many: bool = False):
    conn = db_conn()
    cur = conn.cursor()
    try:
        if many:
            cur.executemany(query, params or [])
        else:
            cur.execute(query, params or ())
        conn.commit()
    finally:
        cur.close()
        conn.close()

def get_local_ipv4s():
    ipv4s = set()
    for _, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if str(a.family).endswith("AF_INET") and a.address != "127.0.0.1":
                ipv4s.add(a.address)
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if ip != "127.0.0.1":
                ipv4s.add(ip)
    except Exception:
        pass
    return sorted(ipv4s)

def ensure_user_in_session():
    if "app_user" not in st.session_state:
        st.session_state.app_user = None

def user_select():
    users = q_df("SELECT user_id, username, role FROM Users ORDER BY username;")
    if users.empty:
        st.warning("No users found. Add at least one user in the Admin tab.")
        return None
    choices = [f"{r.username} ({r.role})" for _, r in users.iterrows()]
    picked = st.selectbox("Select signed-in user", choices, index=0)
    idx = choices.index(picked)
    row = users.iloc[idx]
    return int(row.user_id), row.username, row.role

def insert_alert(alert_type: str, severity: str, message: str, resolved_by=None):
    try:
        q_exec("""
            INSERT INTO System_Alerts (alert_type, severity, message, detected_at, resolved_at, resolved_by)
            VALUES (?, ?, ?, SYSDATETIME(), NULL, ?)
        """, (alert_type, severity, message, resolved_by))
    except Exception:
        # If System_Alerts not present or constraint mismatch, skip silently
        pass

def ping_ok(host: str, timeout=1.5) -> bool:
    if PING3_AVAILABLE:
        try:
            r = ping3_ping(host, timeout=timeout, unit="ms")
            return r is not None
        except Exception:
            return False
    else:
        return _sys_ping_once(host, timeout)  # type: ignore[name-defined]

# =========================
# SIMPLE LOGIN (admin/admin)
# =========================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

def show_login():
    st.title("🔐 Sign In")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")
    col_a, col_b = st.columns([1,1])
    with col_a:
        if st.button("Login", use_container_width=True):
            if u == "admin" and p == "admin":
                st.session_state.logged_in = True
                st.success("Login successful ✅")
                rerun()
            else:
                st.error("Invalid credentials. Use admin / admin.")
    with col_b:
        st.caption("Use your provided admin credentials")

if not st.session_state.logged_in:
    show_login()
    st.stop()

# =========================
# SIDEBAR (Session + Settings)
# =========================
with st.sidebar:
    st.header("🔐 Session")
    ensure_user_in_session()
    if st.session_state.app_user is None:
        picked = user_select()
        if picked:
            st.session_state.app_user = {"id": picked[0], "username": picked[1], "role": picked[2]}
            st.success(f"Signed in as {picked[1]} ({picked[2]})")
    else:
        st.write(f"**Signed in:** {st.session_state.app_user['username']} ({st.session_state.app_user['role']})")
    if st.button("Logout", type="primary"):
        st.session_state.logged_in = False
        st.session_state.app_user = None
        rerun()

    st.divider()
    st.header("🌐 Monitor Settings")
    public_host = st.text_input("Public host to ping", value=PUBLIC_PING_HOST_DEFAULT)
    retail_host = st.text_input("Retail server to ping", value=RETAIL_SERVER_HOST_DEFAULT)
    refresh_ms = st.number_input("Auto-refresh (ms)", min_value=0, value=30000, help="0 disables auto-refresh")
    if refresh_ms and refresh_ms > 0 and AUTORF_AVAILABLE:
        st_autorefresh(interval=refresh_ms, key="auto_refresh_key")
    elif refresh_ms and refresh_ms > 0 and not AUTORF_AVAILABLE:
        st.info("Auto-refresh requested but 'streamlit-autorefresh' is not installed.")

# =========================
# TITLE
# =========================
st.title("Retail Operations Optimization System: IP Management & Hardware Support")

# =========================
# TABS
# =========================
tab_dash, tab_ip, tab_net, tab_sso, tab_hw, tab_alerts, tab_db, tab_admin = st.tabs(
    ["📊 Dashboard", "🌐 IP Manager", "📶 Network Monitor", "🔑 SSO Logs",
     "🧰 Hardware Issues", "🚨 Alerts", "🗄️ DB Browser", "👤 Admin (Users)"]
)

# =========================
# DASHBOARD
# =========================
with tab_dash:
    c1, c2, c3, c4 = st.columns(4)
    def safe_scalar(sql):
        try:
            df = q_df(sql)
            return int(df.iloc[0,0]) if not df.empty else 0
        except Exception:
            return 0

    users_count = safe_scalar("SELECT COUNT(*) AS n FROM Users;")
    open_issues = safe_scalar("SELECT COUNT(*) AS n FROM Hardware_Issues WHERE resolution_status='Pending';")
    alerts_open = safe_scalar("SELECT COUNT(*) AS n FROM System_Alerts WHERE resolved_at IS NULL;")
    sso_today   = safe_scalar("SELECT COUNT(*) AS n FROM SSO_Logins WHERE CAST(login_time AS DATE)=CAST(GETDATE() AS DATE);")

    c1.metric("Users", users_count)
    c2.metric("Open Hardware Issues", open_issues)
    c3.metric("Open Alerts", alerts_open)
    c4.metric("SSO Events Today", sso_today)

    st.subheader("Recent Alerts")
    try:
        rec_alerts = q_df("""
            SELECT TOP (10) alert_id, alert_type, severity, message, detected_at, resolved_at
            FROM System_Alerts
            ORDER BY alert_id DESC;
        """)
        st.dataframe(rec_alerts, use_container_width=True, height=260)
    except Exception:
        st.info("System_Alerts not available yet.")

# =========================
# IP MANAGER
# =========================
with tab_ip:
    st.subheader("Automatic IP Detection & Adjustment")
    if st.session_state.app_user is None:
        st.info("Select a user in the sidebar to log IP events.")
    else:
        ips = get_local_ipv4s()
        st.write("**Detected IPv4 addresses:**")
        st.code("\n".join(ips) if ips else "(none detected)")

        pick_ip = st.selectbox("Choose current active IP", options=ips if ips else [""])
        colA, colB = st.columns(2)

        with colA:
            if st.button("Log Detected IP"):
                if pick_ip:
                    try:
                        q_exec("""
                            INSERT INTO IP_Logs (user_id, detected_ip, adjusted_ip, status, timestamp)
                            VALUES (?, ?, NULL, 'Detected', SYSDATETIME())
                        """, (st.session_state.app_user["id"], pick_ip))
                        insert_alert("IP", "Low", f"Detected IP {pick_ip} for {st.session_state.app_user['username']}.")
                        st.success(f"Logged detected IP: {pick_ip}")
                    except Exception as e:
                        st.error(f"Failed to log IP. Details: {e}")
                else:
                    st.error("No IP selected.")

        with colB:
            new_ip = st.text_input("(Optional) Adjust IP")
            if st.button("Record Adjustment"):
                if pick_ip and new_ip:
                    try:
                        q_exec("""
                            INSERT INTO IP_Logs (user_id, detected_ip, adjusted_ip, status, timestamp)
                            VALUES (?, ?, ?, 'Adjusted', SYSDATETIME())
                        """, (st.session_state.app_user["id"], pick_ip, new_ip))
                        insert_alert("IP", "Medium", f"Adjusted IP from {pick_ip} → {new_ip} for {st.session_state.app_user['username']}.")
                        st.success(f"Adjustment recorded: {pick_ip} → {new_ip}")
                    except Exception as e:
                        st.error(f"Failed to record adjustment. Details: {e}")
                else:
                    st.error("Provide both detected IP and adjusted IP.")

        st.divider()
        st.caption("Recent IP events")
        try:
            ip_hist = q_df("""
                SELECT TOP (20) L.ip_id, U.username, L.detected_ip, L.adjusted_ip, L.status, L.timestamp
                FROM IP_Logs L JOIN Users U ON U.user_id = L.user_id
                ORDER BY L.ip_id DESC;
            """)
            st.dataframe(ip_hist, use_container_width=True)
        except Exception:
            st.info("IP_Logs not available yet.")

# =========================
# NETWORK MONITOR
# =========================
with tab_net:
    st.subheader("Network Uptime Monitor")
    col1, col2 = st.columns(2)
    with col1:
        ok_public = ping_ok(public_host)
        st.metric(f"Public ({public_host})", "Up" if ok_public else "Down")
    with col2:
        ok_retail = ping_ok(retail_host)
        st.metric(f"Retail ({retail_host})", "Up" if ok_retail else "Down")

    now_status = "Up" if ok_retail else "Down"
    try:
        last = q_df("SELECT TOP (1) * FROM Network_Status ORDER BY network_id DESC;")
        if last.empty:
            q_exec("""
                INSERT INTO Network_Status (status, detected_at, resolved_at, downtime_seconds)
                VALUES (?, SYSDATETIME(), NULL, 0);
            """, (now_status,))
            if now_status == "Down":
                insert_alert("Network", "High", f"{retail_host} is DOWN (first record).")
        else:
            last_stat = last.status.iloc[0]
            if last_stat != now_status:
                if now_status == "Down":
                    q_exec("INSERT INTO Network_Status (status, detected_at, resolved_at, downtime_seconds) VALUES ('Down', SYSDATETIME(), NULL, 0);")
                    insert_alert("Network", "High", f"{retail_host} went DOWN.")
                else:
                    open_down = q_df("""
                        SELECT TOP (1) * FROM Network_Status
                        WHERE status='Down' AND resolved_at IS NULL
                        ORDER BY network_id DESC;
                    """)
                    if not open_down.empty:
                        nid = int(open_down.network_id.iloc[0])
                        q_exec("""
                            UPDATE Network_Status
                            SET status='Up', resolved_at=SYSDATETIME(),
                                downtime_seconds = DATEDIFF(SECOND, detected_at, SYSDATETIME())
                            WHERE network_id=?
                        """, (nid,))
                    q_exec("INSERT INTO Network_Status (status, detected_at, resolved_at, downtime_seconds) VALUES ('Up', SYSDATETIME(), NULL, 0);")
                    insert_alert("Network", "Low", f"{retail_host} recovered (UP).")
    except Exception:
        st.info("Network_Status not available yet.")

    st.divider()
    st.caption("Recent Network Status")
    try:
        ns = q_df("""
            SELECT TOP (25) network_id, status, detected_at, resolved_at, downtime_seconds
            FROM Network_Status
            ORDER BY network_id DESC;
        """)
        st.dataframe(ns, use_container_width=True)
    except Exception:
        st.info("Network_Status table not found.")

# =========================
# SSO LOGS
# =========================
with tab_sso:
    st.subheader("SSO Login Events (simulated)")
    if st.session_state.app_user is not None:
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Record SSO Success"):
                try:
                    q_exec("INSERT INTO SSO_Logins (user_id, login_time, status) VALUES (?, SYSDATETIME(), 'Success')",
                           (st.session_state.app_user["id"],))
                    insert_alert("SSO", "Low", f"SSO success for {st.session_state.app_user['username']}.")
                    st.success("SSO Success recorded.")
                except Exception as e:
                    st.error(f"Failed to record SSO. Details: {e}")
        with c2:
            if st.button("Record SSO Failure"):
                try:
                    q_exec("INSERT INTO SSO_Logins (user_id, login_time, status) VALUES (?, SYSDATETIME(), 'Failure')",
                           (st.session_state.app_user["id"],))
                    insert_alert("SSO", "Medium", f"SSO failure for {st.session_state.app_user['username']}.")
                    st.warning("SSO Failure recorded.")
                except Exception as e:
                    st.error(f"Failed to record SSO. Details: {e}")
    else:
        st.info("Select a user in the sidebar to log SSO events.")

    st.divider()
    try:
        sso_logs = q_df("""
            SELECT TOP (50) S.login_id, U.username, S.login_time, S.status
            FROM SSO_Logins S JOIN Users U ON U.user_id=S.user_id
            ORDER BY S.login_id DESC;
        """)
        st.dataframe(sso_logs, use_container_width=True)
    except Exception:
        st.info("SSO_Logins not available yet.")

# =========================
# HARDWARE ISSUES
# =========================
with tab_hw:
    st.subheader("Hardware Troubleshooter & Issue Desk")

    st.markdown("""
**Cartridge Jam Quick Guide**
1. Power off, open panel, remove cartridge gently.  
2. Clear paper/debris; check rollers.  
3. Re-seat cartridge; close panel.  
4. Power on and test.  
If still failing, log an issue and tag *Cartridge_Jam*.
""")

    if st.session_state.app_user is None:
        st.info("Select a user in the sidebar to submit issues.")
    else:
        with st.expander("Report New Issue"):
            issue_type = st.selectbox("Issue Type", ["Cartridge_Jam", "Printer_Error", "Scanner_Error", "Other"])
            desc = st.text_area("Description / Notes")
            if st.button("Submit Issue"):
                try:
                    q_exec("""
                        INSERT INTO Hardware_Issues (user_id, issue_type, description, detected_at, resolved_at, resolution_status)
                        VALUES (?, ?, ?, SYSDATETIME(), NULL, 'Pending')
                    """, (st.session_state.app_user["id"], issue_type, (desc or None)))
                    insert_alert("Hardware", "Medium", f"New issue reported: {issue_type} by {st.session_state.app_user['username']}.")
                    st.success("Issue submitted.")
                except Exception as e:
                    st.error(f"Failed to submit issue. Details: {e}")

    st.divider()
    cA, cB = st.columns(2)
    with cA:
        st.caption("Open Issues")
        try:
            open_df = q_df("""
                SELECT H.issue_id, U.username, H.issue_type, H.description, H.detected_at, H.resolution_status
                FROM Hardware_Issues H JOIN Users U ON U.user_id=H.user_id
                WHERE H.resolution_status='Pending'
                ORDER BY H.issue_id DESC;
            """)
            st.dataframe(open_df, use_container_width=True)
        except Exception:
            st.info("Hardware_Issues not available yet.")

    with cB:
        st.caption("Recently Resolved")
        try:
            res_df = q_df("""
                SELECT TOP (25) H.issue_id, U.username, H.issue_type, H.description, H.detected_at, H.resolved_at
                FROM Hardware_Issues H JOIN Users U ON U.user_id=H.user_id
                WHERE H.resolution_status='Resolved'
                ORDER BY H.resolved_at DESC;
            """)
            st.dataframe(res_df, use_container_width=True)
        except Exception:
            st.info("Hardware_Issues not available yet.")

    st.divider()
    st.caption("Resolve an Issue")
    to_resolve = st.number_input("Issue ID to resolve", min_value=0, step=1, value=0)
    if st.button("Mark Resolved"):
        if to_resolve > 0:
            try:
                q_exec("""
                    UPDATE Hardware_Issues
                    SET resolution_status='Resolved', resolved_at=SYSDATETIME()
                    WHERE issue_id=? AND resolution_status='Pending'
                """, (int(to_resolve),))
                insert_alert("Hardware", "Low", f"Issue {int(to_resolve)} marked Resolved.")
                st.success(f"Issue {int(to_resolve)} resolved (if it was pending).")
            except Exception as e:
                st.error(f"Failed to resolve issue. Details: {e}")
        else:
            st.error("Enter a valid Issue ID.")

# =========================
# ALERTS
# =========================
with tab_alerts:
    st.subheader("System Alerts")
    sev = st.multiselect("Filter severity", ["Low", "Medium", "High", "Critical"])
    base_q = """
        SELECT A.alert_id, A.alert_type, A.severity, A.message, A.detected_at, A.resolved_at, U.username AS resolved_by
        FROM System_Alerts A
        LEFT JOIN Users U ON U.user_id=A.resolved_by
    """
    try:
        if sev:
            placeholders = ",".join(["?"] * len(sev))
            q = base_q + f" WHERE A.severity IN ({placeholders}) ORDER BY A.alert_id DESC OFFSET 0 ROWS FETCH NEXT 200 ROWS ONLY;"
            alerts = q_df(q, tuple(sev))
        else:
            q = base_q + " ORDER BY A.alert_id DESC OFFSET 0 ROWS FETCH NEXT 200 ROWS ONLY;"
            alerts = q_df(q)
        st.dataframe(alerts, use_container_width=True)
    except Exception:
        st.info("System_Alerts not available yet.")

    st.divider()
    st.caption("Resolve an Alert")
    aid = st.number_input("Alert ID to resolve", min_value=0, step=1, value=0)
    if st.button("Mark Alert Resolved"):
        if aid > 0:
            try:
                resolver = st.session_state.app_user["id"] if st.session_state.app_user else None
                q_exec("""
                    UPDATE System_Alerts
                    SET resolved_at=SYSDATETIME(), resolved_by=?
                    WHERE alert_id=? AND resolved_at IS NULL
                """, (resolver, int(aid)))
                st.success(f"Alert {int(aid)} marked resolved (if open).")
            except Exception as e:
                st.error(f"Failed to resolve alert. Details: {e}")
        else:
            st.error("Enter a valid Alert ID.")

# =========================
# DB BROWSER
# =========================
with tab_db:
    st.subheader("Browse Database Tables")
    try:
        tables = q_df("""
            SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME;
        """)
        table_names = tables["TABLE_NAME"].tolist() if not tables.empty else []
    except Exception:
        table_names = []

    if table_names:
        chosen = st.selectbox("Select a table", table_names)
        try:
            df = q_df(f"SELECT TOP (50) * FROM [{chosen}];")
            st.dataframe(df, use_container_width=True, height=420)
        except Exception as e:
            df = pd.DataFrame()
            st.error(f"Failed to read table [{chosen}]: {e}")

        try:
            cols = q_df("""
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_NAME = ?
                ORDER BY ORDINAL_POSITION;
            """, (chosen,))
            with st.expander("Columns"):
                st.dataframe(cols, use_container_width=True)
        except Exception:
            pass

        try:
            c1, c2 = st.columns(2)
            with c1:
                if not df.empty:
                    csv_bytes = df.to_csv(index=False).encode("utf-8")
                    st.download_button("Download CSV", data=csv_bytes, file_name=f"{chosen}.csv", mime="text/csv")
            with c2:
                if not df.empty:
                    out = BytesIO()
                    try:
                        with pd.ExcelWriter(out, engine="openpyxl") as writer:
                            df.to_excel(writer, index=False, sheet_name=(chosen[:31] or "data"))
                    except Exception:
                        with pd.ExcelWriter(out, engine="xlsxwriter") as writer:
                            df.to_excel(writer, index=False, sheet_name=(chosen[:31] or "data"))
                    st.download_button("Download Excel", data=out.getvalue(),
                                       file_name=f"{chosen}.xlsx",
                                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        except Exception:
            pass
    else:
        st.warning("No tables found or cannot access INFORMATION_SCHEMA.")

# =========================
# ADMIN (USERS)
# =========================
with tab_admin:
    st.subheader("User Management (simple)")
    col1, col2, col3 = st.columns(3)
    with col1:
        new_user = st.text_input("Username")
    with col2:
        new_role = st.selectbox("Role", ["Teller", "Admin", "IT_Support"])
    with col3:
        new_pass = st.text_input("Password (optional)", type="password")

    if st.button("Add User"):
        if new_user.strip():
            try:
                password_value = new_pass.strip() if new_pass.strip() else "default_hash"
                q_exec("""
                    INSERT INTO Users (username, password_hash, role, created_at)
                    VALUES (?, ?, ?, SYSDATETIME())
                """, (new_user.strip(), password_value, new_role))
                # Use a valid alert_type to satisfy CHECK constraint (no "Admin" type)
                insert_alert("Monitoring", "Low", f"New user added: {new_user.strip()}")
                st.success(f"User '{new_user}' created.")
                rerun()
            except Exception as e:
                st.error(f"Failed to add user. Details: {e}")
        else:
            st.error("Enter a username.")

    st.divider()
    st.caption("Current Users")
    try:
        udf = q_df("""
            SELECT user_id, username, role,
                   COALESCE(created_at, SYSDATETIME()) AS created_at
            FROM Users
            ORDER BY user_id DESC;
        """)
        st.dataframe(udf, use_container_width=True)
    except Exception:
        st.info("Users table not available yet.")
