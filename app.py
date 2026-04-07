from flask import Flask, render_template, request, redirect, session
from flask_wtf import CSRFProtect
import sqlite3
import os
import re
import json
import secrets
from uuid import uuid4
from urllib.parse import urlencode
import psutil
import calendar
from datetime import date
from datetime import datetime, timedelta
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")
csrf = CSRFProtect(app)
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
# SECURITY FIX: limit total request upload size to reduce abuse and oversized file attacks.
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
USER_PFP_FOLDER = os.path.join("static", "uploads", "users")
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
# SECURITY FIX: only allow expected upload extensions for user-provided files.
ALLOWED_UPLOAD_EXTENSIONS = ALLOWED_IMAGE_EXTENSIONS | {"pdf"}
ALLOWED_IMAGE_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
}
# SECURITY FIX: use MIME validation as an extra defense in depth.
ALLOWED_UPLOAD_MIME_TYPES = ALLOWED_IMAGE_MIME_TYPES | {"application/pdf"}
ALLOWED_USER_SCHEMA_COLUMNS = ("name", "email", "phone", "staff_id", "department")
DATE_FORMAT = "%Y-%m-%d"
DATETIME_LOCAL_FORMAT = "%Y-%m-%dT%H:%M"
FILENAME_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"
DISPLAY_DATETIME_FORMAT = "%d %b %Y, %H:%M"
DISPLAY_DAY_FORMAT = "%d %b"
NUMERIC_ID_PATTERN = re.compile(r"[0-9]+")
SAFE_TEXT_PATTERN = re.compile(r"^[A-Za-z0-9\s@._:/#,+()\-]{1,100}$")
USERNAME_PATTERN = re.compile(r"^\w{3,30}$")
FLIGHT_NUMBER_PATTERN = re.compile(r"^\w{2,20}$")
GATE_PATTERN = re.compile(r"^[A-Z][0-9]{1,2}$")
SEAT_PATTERN = re.compile(r"^[A-Z][0-9]{1,2}$")
PASSPORT_PATTERN = re.compile(r"^[0-9]{8}$")
TAG_PATTERN = re.compile(r"^\w{2,30}$")
PHONE_PATTERN = re.compile(r"^[0-9]{8}$")
STAFF_ID_PATTERN = re.compile(r"^\w{1,30}$")
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
SQLI_PATTERN = re.compile(
    r"(--|/\*|\*/|;|\b(select|union|drop|insert|delete|update|alter|pragma|attach|detach)\b)",
    re.IGNORECASE
)
FLIGHT_STATUS_CHOICES = {"On Time", "Boarding", "Delayed", "Cancelled"}
BAGGAGE_STATUS_CHOICES = {"Loaded", "In Transit", "Delayed", "Arrived", "Checked In"}
ROLE_CHOICES = {"admin", "staff"}
FILTER_TYPE_CHOICES = {"day", "week", "month", "year"}
SEARCH_RESULTS_TEMPLATE = "search_results.html"
SEARCH_RESULTS_DEFAULT_FILTER_TYPE = "day"
SEARCH_FIELD_MAX_LENGTH = 60
PASSWORD_STATUS_MAX_LENGTH = 20
PASSWORD_MESSAGE_MAX_LENGTH = 120
JS_CLOSEST_FORM_SUBMIT_PATTERN = re.compile(r"this\.closest\((['\"])form\1\)\.submit\(\)")
JS_FUNCTION_CALL_PATTERN = re.compile(r"([A-Za-z_$][\w$]*)\((.*)\)")
JS_NUMERIC_LITERAL_PATTERN = re.compile(r"-?\d+(?:\.\d+)?")
JS_QUOTED_STRING_PATTERN = re.compile(r"""(['"])(.*)\1""")
STYLE_ATTRIBUTE_PATTERN = re.compile(r"\sstyle\s*=\s*(\"([^\"]*)\"|'([^']*)')", re.IGNORECASE)
CLASS_ATTRIBUTE_PATTERN = re.compile(r'\bclass\s*=\s*("([^"]*)"|\'([^\']*)\')', re.IGNORECASE)
EVENT_ATTRIBUTE_PATTERN = re.compile(r"\s(on[a-z]+)\s*=\s*(\"([^\"]*)\"|'([^']*)')", re.IGNORECASE)
CURRENT_MONTH_FLIGHTS_QUERY = """
SELECT id, flight_number, departure, destination, gate, time, status
FROM flights
WHERE strftime('%m', time) = strftime('%m', 'now')
ORDER BY time
"""
FLIGHT_SEARCH_BASE_QUERY = """
SELECT id, flight_number, departure, destination, gate, time, status
FROM flights
WHERE departure LIKE ? ESCAPE '\\'
AND destination LIKE ? ESCAPE '\\'
"""


# SECURITY FIX: central validation helpers keep SQL inputs constrained before any query runs.
def has_malicious_pattern(value):
    return bool(value and SQLI_PATTERN.search(value))


def normalize_datetime_value(value, value_format, field_name, allow_empty):
    value = (value or "").strip()

    if not value:
        if allow_empty:
            return ""
        raise ValueError(f"{field_name} is required")

    try:
        return datetime.strptime(value, value_format).strftime(value_format)
    except ValueError as error:
        raise ValueError(f"Invalid {field_name}") from error


# SECURITY FIX: generic safe text validator for names, cities, and other free-text fields.
def safe_text(value, field_name="field", allow_empty=True, max_length=100, pattern=SAFE_TEXT_PATTERN):
    value = (value or "").strip()

    if not value:
        if allow_empty:
            return ""
        raise ValueError(f"{field_name} is required")

    if len(value) > max_length:
        raise ValueError(f"{field_name} is too long")

    if has_malicious_pattern(value) or not pattern.fullmatch(value):
        raise ValueError(f"Invalid {field_name}")

    return value


# SECURITY FIX: ids are normalized to positive integers before being used in queries.
def safe_id(value, field_name="id", allow_empty=False):
    value = str(value or "").strip()

    if not value:
        if allow_empty:
            return None
        raise ValueError(f"{field_name} is required")

    if not NUMERIC_ID_PATTERN.fullmatch(value):
        raise ValueError(f"Invalid {field_name}")

    parsed_value = int(value)
    if parsed_value <= 0:
        raise ValueError(f"Invalid {field_name}")

    return parsed_value


# SECURITY FIX: LIKE filters escape wildcard characters so users cannot widen matches with % or _.
def escape_like_value(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def safe_like_text(value, field_name="field", max_length=100):
    sanitized = safe_text(value, field_name=field_name, allow_empty=True, max_length=max_length)
    if not sanitized:
        return ""
    return f"%{escape_like_value(sanitized)}%"


# SECURITY FIX: choices are whitelisted so input cannot influence SQL structure or logic branches.
def safe_choice(value, choices, default=None, field_name="field", allow_empty=False):
    value = (value or "").strip()

    if not value:
        if allow_empty:
            return ""
        if default is not None:
            return default
        raise ValueError(f"{field_name} is required")

    if value not in choices:
        if default is not None:
            return default
        raise ValueError(f"Invalid {field_name}")

    return value


def safe_date_value(value, field_name="date", allow_empty=True):
    return normalize_datetime_value(value, DATE_FORMAT, field_name, allow_empty)


def safe_datetime_local(value, field_name="datetime", allow_empty=False):
    return normalize_datetime_value(value, DATETIME_LOCAL_FORMAT, field_name, allow_empty)


def safe_username(value, allow_empty=False):
    value = (value or "").strip()

    if not value:
        if allow_empty:
            return ""
        raise ValueError("Username is required")

    if has_malicious_pattern(value) or not USERNAME_PATTERN.fullmatch(value):
        raise ValueError("Invalid username format")

    return value


def safe_redirect_path(value, default="/flights"):
    value = (value or "").strip()
    if value.startswith("/") and "://" not in value and "\\" not in value:
        return value
    return default


def safe_query_message(value, max_length=120):
    try:
        return safe_text(value, field_name="message", allow_empty=True, max_length=max_length)
    except ValueError:
        return ""


# SECURITY FIX: extract extensions from sanitized names only and never trust raw path fragments.
def get_file_extension(filename):
    sanitized_name = secure_filename(filename or "")
    if "." not in sanitized_name:
        return ""
    return sanitized_name.rsplit(".", 1)[1].lower()


def allowed_file_extension(filename, allowed_extensions):
    return get_file_extension(filename) in allowed_extensions


def allowed_mime_type(file_storage, allowed_mime_types):
    return (file_storage.mimetype or "").lower() in allowed_mime_types


# SECURITY FIX: generate unique server-side filenames to prevent overwrite and path traversal attacks.
def build_unique_filename(original_filename, prefix="upload"):
    sanitized_original = secure_filename(original_filename or "")
    extension = get_file_extension(sanitized_original)
    safe_prefix = secure_filename(prefix or "upload") or "upload"
    timestamp = datetime.utcnow().strftime(FILENAME_TIMESTAMP_FORMAT)
    unique_suffix = uuid4().hex

    if extension:
        return f"{safe_prefix}_{timestamp}_{unique_suffix}.{extension}"

    return f"{safe_prefix}_{timestamp}_{unique_suffix}"


# SECURITY FIX: centralize upload validation and saving so every file path gets the same protections.
def save_uploaded_file(file_storage, target_dir, allowed_extensions, allowed_mime_types, prefix="upload"):
    if not file_storage:
        return "", "No file uploaded."

    original_filename = (file_storage.filename or "").strip()
    if not original_filename:
        return "", "No file selected."

    if not allowed_file_extension(original_filename, allowed_extensions):
        return "", "Invalid file type. Only images and PDF files are allowed."

    if allowed_mime_types and not allowed_mime_type(file_storage, allowed_mime_types):
        return "", "Invalid file type. Only images and PDF files are allowed."

    os.makedirs(target_dir, exist_ok=True)
    filename = build_unique_filename(original_filename, prefix=prefix)
    file_storage.save(os.path.join(target_dir, filename))
    return filename, ""


def db():
    return sqlite3.connect("database.db")


def is_password_hash(value):
    return isinstance(value, str) and value.count("$") >= 2


def password_matches(stored_password, provided_password):
    if not stored_password:
        return False

    if is_password_hash(stored_password):
        return check_password_hash(stored_password, provided_password)

    return stored_password == provided_password


def ensure_user_profile_schema():
    conn = db()
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
    except sqlite3.OperationalError:
        conn.close()
        return

    if "pfp" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN pfp TEXT")
        conn.commit()

    # SECURITY FIX: use a static whitelist for schema changes instead of string-built SQL from variables.
    for column_name in ALLOWED_USER_SCHEMA_COLUMNS:
        if column_name not in columns:
            if column_name == "name":
                cursor.execute("ALTER TABLE users ADD COLUMN name TEXT")
            elif column_name == "email":
                cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
            elif column_name == "phone":
                cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
            elif column_name == "staff_id":
                cursor.execute("ALTER TABLE users ADD COLUMN staff_id TEXT")
            elif column_name == "department":
                cursor.execute("ALTER TABLE users ADD COLUMN department TEXT")
            conn.commit()

    try:
        cursor.execute("UPDATE users SET name = username WHERE name IS NULL OR name = ''")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    conn.close()


def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def save_user_profile_image(file_storage, username):
    # SECURITY FIX: profile images use the centralized safe upload pipeline.
    safe_name = secure_filename(username or "user") or "user"
    filename, _ = save_uploaded_file(
        file_storage,
        USER_PFP_FOLDER,
        ALLOWED_IMAGE_EXTENSIONS,
        ALLOWED_IMAGE_MIME_TYPES,
        prefix=safe_name
    )
    return filename


def add_months(value, months):
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def parse_datetime_value(value, value_format):
    return datetime.strptime(value, value_format)


def compute_filter_end_date(start_date, filter_type, selected_end_date=""):
    if filter_type == "day":
        return start_date + timedelta(days=1)
    if selected_end_date:
        return parse_datetime_value(selected_end_date, DATE_FORMAT) + timedelta(days=1)
    if filter_type == "week":
        return start_date + timedelta(days=7)
    if filter_type == "month":
        return add_months(start_date, 1)
    return add_months(start_date, 12)


def build_filter_date_params(selected_date, filter_type, selected_end_date=""):
    if not selected_date:
        return None

    start_date = parse_datetime_value(selected_date, DATE_FORMAT)
    end_date = compute_filter_end_date(start_date, filter_type, selected_end_date)

    if end_date <= start_date:
        raise ValueError("End date must be after the start date.")

    return start_date.strftime(DATE_FORMAT), end_date.strftime(DATE_FORMAT)


def parse_search_fields(form_data):
    departure = safe_text(
        form_data["departure"],
        field_name="departure",
        allow_empty=True,
        max_length=SEARCH_FIELD_MAX_LENGTH,
    )
    destination = safe_text(
        form_data["destination"],
        field_name="destination",
        allow_empty=True,
        max_length=SEARCH_FIELD_MAX_LENGTH,
    )

    return {
        "departure": departure,
        "destination": destination,
        "departure_like": safe_like_text(
            departure,
            field_name="departure",
            max_length=SEARCH_FIELD_MAX_LENGTH,
        ),
        "destination_like": safe_like_text(
            destination,
            field_name="destination",
            max_length=SEARCH_FIELD_MAX_LENGTH,
        ),
    }


def build_flight_search_query(departure_like, destination_like, start_date=None, end_date=None):
    query = FLIGHT_SEARCH_BASE_QUERY
    params = [departure_like or "%", destination_like or "%"]

    if start_date and end_date:
        query += " AND datetime(time) >= datetime(?) AND datetime(time) < datetime(?)"
        params.extend([start_date, end_date])

    return query, params


def fetch_flight_search_results(cursor, flights):
    results = []

    for flight in flights:
        flight_id = flight[0]

        cursor.execute(
            """
        SELECT name, passport, seat
        FROM passengers
        WHERE flight_id=?
        """,
            (flight_id,),
        )

        passengers = cursor.fetchall()

        cursor.execute(
            """
        SELECT tag, weight, location
        FROM baggage
        WHERE flight_id=?
        """,
            (flight_id,),
        )
        cursor.fetchall()

        results.append({
            "flight": flight,
            "passengers": passengers,
        })

    return results


def render_search_results(
    results,
    departure="",
    destination="",
    selected_date="",
    selected_end_date="",
    filter_type=SEARCH_RESULTS_DEFAULT_FILTER_TYPE,
    filter_error="",
    filter_summary="",
):
    return render_template(
        SEARCH_RESULTS_TEMPLATE,
        results=results,
        departure=departure,
        destination=destination,
        selected_date=selected_date,
        selected_end_date=selected_end_date,
        filter_type=filter_type,
        filter_error=filter_error,
        filter_summary=filter_summary,
    )


def build_filter_summary(filter_type, selected_date, selected_end_date):
    if not selected_date:
        return ""

    if filter_type == "day":
        return f"Showing flights for {selected_date}"

    if selected_end_date:
        return f"Showing flights from {selected_date} to {selected_end_date}"

    return f"Showing flights from {selected_date} using the {filter_type} range"


def parse_baggage_filters(values, default_filter_type=SEARCH_RESULTS_DEFAULT_FILTER_TYPE):
    try:
        return {
            "selected_flight_id": safe_id(values.get("flight", ""), field_name="flight", allow_empty=True),
            "selected_date": safe_date_value(values.get("date", ""), field_name="date", allow_empty=True),
            "selected_end_date": safe_date_value(values.get("end_date", ""), field_name="end date", allow_empty=True),
            "filter_type": safe_choice(
                values.get("filter", default_filter_type),
                FILTER_TYPE_CHOICES,
                default=default_filter_type,
                field_name="filter",
                allow_empty=default_filter_type == "",
            ),
        }
    except ValueError:
        return {
            "selected_flight_id": None,
            "selected_date": "",
            "selected_end_date": "",
            "filter_type": default_filter_type,
        }


def build_baggage_redirect_params(selected_flight_id, selected_date, selected_end_date, filter_type):
    params = {}
    if selected_flight_id:
        params["flight"] = selected_flight_id
    if selected_date:
        params["date"] = selected_date
    if selected_end_date:
        params["end_date"] = selected_end_date
    if filter_type:
        params["filter"] = filter_type
    return params


def calculate_delay_minutes(time_value):
    try:
        scheduled = parse_datetime_value(time_value, DATETIME_LOCAL_FORMAT)
        delay_minutes = int((datetime.now() - scheduled).total_seconds() / 60)
        return max(delay_minutes, 0)
    except Exception:
        return None


def fetch_current_month_flights():
    conn = db()
    cursor = conn.cursor()
    cursor.execute(CURRENT_MONTH_FLIGHTS_QUERY)
    flights = cursor.fetchall()
    conn.close()
    return flights


def build_user_password_redirect(status, message):
    return redirect("/users?" + urlencode({
        "password_status": status,
        "password_message": message,
    }))


def current_user_is_admin():
    user_id = session.get("user_id")

    if not user_id:
        return False

    conn = db()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT role FROM users WHERE id=?", (user_id,))
        row = cursor.fetchone()
    except sqlite3.OperationalError:
        row = None

    conn.close()

    return bool(row and row[0] == "admin")


def get_current_user_profile():
    user_id = session.get("user_id")

    if not user_id:
        return None

    conn = db()
    cursor = conn.cursor()

    try:
        cursor.execute("""
        SELECT id, username, role, pfp, name, email, phone, staff_id, department, password
        FROM users
        WHERE id=?
        LIMIT 1
        """, (user_id,))
        row = cursor.fetchone()
    except sqlite3.OperationalError:
        row = None

    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "username": row[1],
        "role": row[2] or "staff",
        "pfp": row[3] or "",
        "name": row[4] or row[1],
        "email": row[5] or "",
        "phone": row[6] or "",
        "staff_id": row[7] or "",
        "department": row[8] or "",

        "password": row[9] or ""
    }

@app.after_request
def add_security_headers(response):
    csp_nonce = secrets.token_urlsafe(16)

    if response.mimetype == "text/html":
        html = response.get_data(as_text=True)
        inline_style_classes = {}
        event_bindings = []

        def build_style_class(style_value):
            normalized_style = style_value.strip()
            if normalized_style not in inline_style_classes:
                inline_style_classes[normalized_style] = f"csp-inline-style-{len(inline_style_classes) + 1}"
            return inline_style_classes[normalized_style]

        def build_event_action(handler_value):
            normalized_handler = handler_value.strip().rstrip(";")

            if JS_CLOSEST_FORM_SUBMIT_PATTERN.fullmatch(normalized_handler):
                return "const form = element.closest('form'); if (form) { form.submit(); }"

            function_match = JS_FUNCTION_CALL_PATTERN.fullmatch(normalized_handler)
            if not function_match:
                return None

            function_name, raw_argument = function_match.groups()
            raw_argument = raw_argument.strip()

            if not raw_argument:
                return (
                    f"if (typeof window[{json.dumps(function_name)}] === 'function') "
                    f"{{ window[{json.dumps(function_name)}](); }}"
                )

            if JS_NUMERIC_LITERAL_PATTERN.fullmatch(raw_argument) or raw_argument in {"true", "false", "null"}:
                argument_expression = raw_argument
            else:
                string_match = JS_QUOTED_STRING_PATTERN.fullmatch(raw_argument)
                if not string_match:
                    return None
                argument_expression = json.dumps(string_match.group(2))

            return (
                f"if (typeof window[{json.dumps(function_name)}] === 'function') "
                f"{{ window[{json.dumps(function_name)}]({argument_expression}); }}"
            )

        def transform_opening_tag(match):
            tag_markup = match.group(0)

            style_match = STYLE_ATTRIBUTE_PATTERN.search(tag_markup)
            if style_match:
                style_value = style_match.group(2) or style_match.group(3) or ""
                style_class = build_style_class(style_value)
                tag_markup = STYLE_ATTRIBUTE_PATTERN.sub("", tag_markup, count=1)

                class_match = CLASS_ATTRIBUTE_PATTERN.search(tag_markup)
                if class_match:
                    current_classes = (class_match.group(2) or class_match.group(3) or "").split()
                    if style_class not in current_classes:
                        current_classes.append(style_class)
                    tag_markup = CLASS_ATTRIBUTE_PATTERN.sub(
                        f'class="{" ".join(current_classes)}"',
                        tag_markup,
                        count=1
                    )
                else:
                    tag_markup = tag_markup[:-1] + f' class="{style_class}">'

            element_event_id = None

            def replace_event_attribute(event_match):
                nonlocal element_event_id
                event_name = (event_match.group(1) or "")[2:].lower()
                handler_value = event_match.group(3) or event_match.group(4) or ""
                event_action = build_event_action(handler_value)

                if not event_action:
                    return event_match.group(0)

                if not element_event_id:
                    element_event_id = f"csp-event-{len(event_bindings) + 1}"

                event_bindings.append((element_event_id, event_name, event_action))
                return ""

            tag_markup = EVENT_ATTRIBUTE_PATTERN.sub(replace_event_attribute, tag_markup)

            if element_event_id:
                tag_markup = tag_markup[:-1] + f' data-csp-event-id="{element_event_id}">'

            return tag_markup

        def add_nonce_to_style(match):
            return f'<style nonce="{csp_nonce}"{match.group(1)}>'

        def add_nonce_to_script(match):
            return f'<script nonce="{csp_nonce}"{match.group(1)}>'

        html = re.sub(
            r"<style(?![^>]*\bnonce=)([^>]*)>",
            add_nonce_to_style,
            html,
            flags=re.IGNORECASE,
        )
        html = re.sub(
            r"<script(?![^>]*\bsrc=)(?![^>]*\bnonce=)([^>]*)>",
            add_nonce_to_script,
            html,
            flags=re.IGNORECASE,
        )

        html = re.sub(r"<[A-Za-z][^<>]*>", transform_opening_tag, html)

        if inline_style_classes:
            generated_styles = "\n".join(
                f".{class_name} {{ {style_value} }}"
                for style_value, class_name in inline_style_classes.items()
            )
            style_block = f'<style nonce="{csp_nonce}">\n{generated_styles}\n</style>'
            if "</head>" in html:
                html = html.replace("</head>", style_block + "\n</head>", 1)
            else:
                html = style_block + html

        if event_bindings:
            listener_lines = ["document.addEventListener('DOMContentLoaded', function () {"]
            for index, (event_id, event_name, event_action) in enumerate(event_bindings, start=1):
                selector = f'[data-csp-event-id="{event_id}"]'
                listener_lines.append(f"  const element{index} = document.querySelector({json.dumps(selector)});")
                listener_lines.append(f"  if (element{index}) {{")
                listener_lines.append(
                    f"    element{index}.addEventListener({json.dumps(event_name)}, function (event) {{"
                )
                listener_lines.append("      const element = event.currentTarget;")
                listener_lines.append(f"      {event_action}")
                listener_lines.append("    });")
                listener_lines.append("  }")
            listener_lines.append("});")
            listener_script = '<script nonce="{0}">\n{1}\n</script>'.format(
                csp_nonce,
                "\n".join(listener_lines)
            )
            if "</body>" in html:
                html = html.replace("</body>", listener_script + "\n</body>", 1)
            else:
                html += listener_script

        response.set_data(html)

    script_sources = [
        "'self'",
        f"'nonce-{csp_nonce}'",
        "https://cdn.jsdelivr.net",
        "https://unpkg.com",
    ]

    style_sources = [
        "'self'",
        f"'nonce-{csp_nonce}'",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com",
        "https://fonts.googleapis.com",
        "https://unpkg.com",
    ]

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        f"style-src {' '.join(style_sources)}; "
        f"script-src {' '.join(script_sources)}; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "img-src 'self' data: https://images.unsplash.com https://flagcdn.com https://tile.openstreetmap.org https://*.tile.openstreetmap.org https://unpkg.com; "
        "connect-src 'self' https://tile.openstreetmap.org https://*.tile.openstreetmap.org; "
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()"
    response.headers["Cross-Origin-Embedder-Policy"] = "credentialless"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.context_processor
def inject_admin_profile():
    conn = db()
    cursor = conn.cursor()
    current_user_id = session.get("user_id")
    try:
        if current_user_id:
            cursor.execute("""
            SELECT username, role, pfp
            FROM users
            WHERE id=?
            LIMIT 1
            """, (current_user_id,))
            admin = cursor.fetchone()
        else:
            admin = None
    except sqlite3.OperationalError:
        admin = None
    conn.close()

    return {
        "admin_profile": admin,
        "is_admin": current_user_is_admin()
    }


ensure_user_profile_schema()


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    # SECURITY FIX: return a safe message instead of leaking framework internals on oversized uploads.
    return "File too large. Maximum allowed size is 8 MB.", 413


@app.route("/")
def home():
    return redirect("/login")


@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        try:
            # SECURITY FIX: validate username before it reaches authentication queries.
            username = safe_username(username)
        except ValueError as error:
            return render_template("login.html", login_error=str(error))

        conn = db()
        c = conn.cursor()

        user = c.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if user and password_matches(user[2], password):
            if not is_password_hash(user[2]):
                c.execute(
                    "UPDATE users SET password=? WHERE id=?",
                    (generate_password_hash(password), user[0])
                )
                conn.commit()
            session["user_id"] = user[0]
            conn.close()
            return redirect("/dashboard")

        conn.close()
        return render_template("login.html", login_error="Wrong username or password")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")


@app.route("/edit-profile")
def edit_profile():
    user = get_current_user_profile()

    if not user:
        return redirect("/login")

    return render_template(
        "edit_profile.html",
        user=user,
        role_editable=current_user_is_admin(),
        profile_error="",
        profile_success=safe_query_message(request.args.get("updated", ""), max_length=1) == "1"
    )


@app.route("/update-profile", methods=["POST"])
def update_profile():
    user = get_current_user_profile()

    if not user:
        return redirect("/login")

    try:
        # SECURITY FIX: validate all editable profile fields before persisting or querying.
        name = safe_text(request.form.get("name", ""), field_name="name", allow_empty=False)
        email = safe_text(request.form.get("email", ""), field_name="email", allow_empty=True, max_length=100, pattern=EMAIL_PATTERN) if request.form.get("email", "").strip() else ""
        phone = request.form.get("phone", "").replace(" ", "").strip()
        staff_id = safe_text(request.form.get("staff_id", ""), field_name="staff ID", allow_empty=False, max_length=30, pattern=STAFF_ID_PATTERN)
        department = safe_text(request.form.get("department", ""), field_name="department", allow_empty=True, max_length=60)
        requested_role = safe_choice(request.form.get("role", user["role"]), ROLE_CHOICES, default=user["role"], field_name="role")
    except ValueError as error:
        user.update({
            "name": request.form.get("name", "").strip() or user["name"],
            "email": request.form.get("email", "").strip(),
            "phone": request.form.get("phone", "").replace(" ", "").strip(),
            "staff_id": request.form.get("staff_id", "").strip(),
            "department": request.form.get("department", "").strip(),
            "role": request.form.get("role", user["role"]).strip() or user["role"]
        })
        return render_template(
            "edit_profile.html",
            user=user,
            role_editable=current_user_is_admin(),
            profile_error=str(error),
            profile_success=False
        )

    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    pfp_file = request.files.get("pfp")

    if new_password or confirm_password:
        if new_password != confirm_password:
            user.update({
                "name": name or user["name"],
                "email": email,
                "phone": phone,
                "staff_id": staff_id,
                "department": department,
                "role": requested_role
            })
            return render_template(
                "edit_profile.html",
                user=user,
                role_editable=current_user_is_admin(),
                profile_error="Passwords do not match.",
                profile_success=False
            )

    if phone and not PHONE_PATTERN.fullmatch(phone):
        user.update({
            "name": name or user["name"],
            "email": email,
            "phone": phone,
            "staff_id": staff_id,
            "department": department,
            "role": requested_role
        })
        return render_template(
            "edit_profile.html",
            user=user,
            role_editable=current_user_is_admin(),
            profile_error="Phone number must contain exactly 8 digits.",
            profile_success=False
        )

    if not staff_id:
        user.update({
            "name": name or user["name"],
            "email": email,
            "phone": phone,
            "staff_id": staff_id,
            "department": department,
            "role": requested_role
        })
        return render_template(
            "edit_profile.html",
            user=user,
            role_editable=current_user_is_admin(),
            profile_error="Staff ID is required.",
            profile_success=False
        )

    role_to_save = requested_role if current_user_is_admin() else user["role"]
    password_to_save = generate_password_hash(new_password) if new_password else user["password"]
    pfp_to_save = user["pfp"]

    if pfp_file and pfp_file.filename:
        pfp_filename = save_user_profile_image(pfp_file, user["username"])
        if pfp_filename:
            if user["pfp"]:
                old_path = os.path.join(USER_PFP_FOLDER, user["pfp"])
                if os.path.exists(old_path):
                    os.remove(old_path)
            pfp_to_save = pfp_filename

    conn = db()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE users
    SET name=?,
        email=?,
        phone=?,
        staff_id=?,
        department=?,
        role=?,
        password=?,
        pfp=?
    WHERE id=?
    """, (name, email, phone, staff_id, department, role_to_save, password_to_save, pfp_to_save, user["id"]))
    conn.commit()
    conn.close()

    return redirect("/edit-profile?updated=1")


@app.route("/dashboard")
def dashboard():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT COUNT(*) FROM flights
    WHERE date(time) = date('now')
    """)
    flights_today = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM passengers")
    passengers_today = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM flights WHERE status='Delayed'")
    delayed_flights = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(DISTINCT gate)
    FROM flights
    WHERE date(time) = date('now')
    """)
    active_gates = cursor.fetchone()[0]

    # get countries list
    cursor.execute("""
    SELECT DISTINCT departure FROM flights
    UNION
    SELECT DISTINCT destination FROM flights
    """)

    countries = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        flights_today=flights_today,
        passengers_today=passengers_today,
        delayed_flights=delayed_flights,
        active_gates=active_gates,
        countries=countries
    )


@app.route("/flights")
def flights():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, flight_number, departure, destination, gate, time, status
        FROM flights
        ORDER BY datetime(time) ASC
    """)

    flights = cursor.fetchall()

    conn.close()

    return render_template("flights.html", flights=flights)


@app.route("/flights_dashboard")
def flights_dashboard():

    conn = db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, flight_number, departure, destination, gate, time, status
        FROM flights
        ORDER BY datetime(time) ASC
    """)
    flights = cursor.fetchall()

    total_flights = len(flights)
    on_time = sum(1 for flight in flights if flight[6] == "On Time")
    boarding = sum(1 for flight in flights if flight[6] == "Boarding")
    delayed = sum(1 for flight in flights if flight[6] == "Delayed")
    cancelled = sum(1 for flight in flights if flight[6] == "Cancelled")
    active_gates = len({flight[4] for flight in flights})

    now = datetime.now()
    upcoming_flights = []
    route_counts = {}
    gate_counts = {}
    next_seven_days = {}
    country_code_map = {
        "Tunis": "tn",
        "Paris": "fr",
        "Rome": "it",
        "Dubai": "ae",
        "Frankfurt": "de",
        "Madrid": "es",
        "Algiers": "dz",
        "Alger": "dz",
        "London": "gb",
        "Istanbul": "tr",
        "Doha": "qa",
    }
    city_coordinates = {
        "Tunis": {"lat": 36.8065, "lng": 10.1815},
        "Paris": {"lat": 48.8566, "lng": 2.3522},
        "Rome": {"lat": 41.9028, "lng": 12.4964},
        "Dubai": {"lat": 25.2048, "lng": 55.2708},
        "Frankfurt": {"lat": 50.1109, "lng": 8.6821},
        "Madrid": {"lat": 40.4168, "lng": -3.7038},
        "Algiers": {"lat": 36.7538, "lng": 3.0588},
        "Alger": {"lat": 36.7538, "lng": 3.0588},
        "London": {"lat": 51.5072, "lng": -0.1276},
        "Istanbul": {"lat": 41.0082, "lng": 28.9784},
        "Doha": {"lat": 25.2854, "lng": 51.5310},
    }

    for flight in flights:
        try:
            scheduled = parse_datetime_value(flight[5], DATETIME_LOCAL_FORMAT)
        except ValueError:
            continue

        if scheduled >= now and len(upcoming_flights) < 6:
            upcoming_flights.append({
                "flight_number": flight[1],
                "departure": flight[2],
                "destination": flight[3],
                "gate": flight[4],
                "time": scheduled.strftime(DISPLAY_DATETIME_FORMAT),
                "status": flight[6],
            })

        route_key = f"{flight[2]} -> {flight[3]}"
        route_counts[route_key] = route_counts.get(route_key, 0) + 1
        gate_counts[flight[4]] = gate_counts.get(flight[4], 0) + 1

        date_key = scheduled.strftime(DISPLAY_DAY_FORMAT)
        if (scheduled.date() - now.date()).days in range(0, 7):
            next_seven_days[date_key] = next_seven_days.get(date_key, 0) + 1

    top_routes = sorted(route_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    busiest_gates = sorted(gate_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    weekly_load = [{"label": label, "count": count} for label, count in sorted(next_seven_days.items())]
    max_weekly_load = max((item["count"] for item in weekly_load), default=1)
    route_map_cities = []
    route_map_lines = []

    for city, position in city_coordinates.items():
        route_map_cities.append({
            "name": city,
            "lat": position["lat"],
            "lng": position["lng"],
        })

    for flight in flights[:16]:
        departure = city_coordinates.get(flight[2])
        destination = city_coordinates.get(flight[3])

        if not departure or not destination:
            continue

        route_map_lines.append({
            "flight_number": flight[1],
            "departure": flight[2],
            "destination": flight[3],
            "lat1": departure["lat"],
            "lng1": departure["lng"],
            "lat2": destination["lat"],
            "lng2": destination["lng"],
            "status": flight[6],
            "time": flight[5],
        })

    country_stats = {}
    for period_name, days in {"weekly": 7, "monthly": 30, "yearly": 365}.items():
        current_start = now
        current_end = now + timedelta(days=days)
        previous_start = now - timedelta(days=days)
        previous_end = now
        current_counts = {}
        previous_counts = {}

        for flight in flights:
            try:
                scheduled = parse_datetime_value(flight[5], DATETIME_LOCAL_FORMAT)
            except ValueError:
                continue

            locations = (
                (flight[2], "departures"),
                (flight[3], "arrivals"),
            )

            for location, key in locations:
                if current_start <= scheduled < current_end:
                    entry = current_counts.setdefault(location, {
                        "country": location,
                        "flag_url": f"https://flagcdn.com/w40/{country_code_map[location]}.png" if location in country_code_map else "",
                        "total": 0,
                        "departures": 0,
                        "arrivals": 0,
                    })
                    entry["total"] += 1
                    entry[key] += 1

                if previous_start <= scheduled < previous_end:
                    previous_counts[location] = previous_counts.get(location, 0) + 1

        rows = []
        for index, (location, values) in enumerate(
            sorted(current_counts.items(), key=lambda item: item[1]["total"], reverse=True)[:7],
            start=1
        ):
            previous_total = previous_counts.get(location, 0)
            current_total = values["total"]

            if previous_total == 0:
                growth_label = "New"
                growth_tone = "up"
            else:
                change = ((current_total - previous_total) / previous_total) * 100
                growth_label = f"{change:+.1f}%"
                if change > 0:
                    growth_tone = "up"
                elif change < 0:
                    growth_tone = "down"
                else:
                    growth_tone = "flat"

            rows.append({
                "id": index,
                "country": values["country"],
                "flag_url": values["flag_url"],
                "total": values["total"],
                "growth": growth_label,
                "growth_tone": growth_tone,
                "departures": values["departures"],
                "arrivals": values["arrivals"],
            })

        country_stats[period_name] = rows

    conn.close()

    return render_template(
        "flights_dashboard.html",
        total_flights=total_flights,
        on_time=on_time,
        boarding=boarding,
        delayed=delayed,
        cancelled=cancelled,
        active_gates=active_gates,
        upcoming_flights=upcoming_flights,
        top_routes=top_routes,
        busiest_gates=busiest_gates,
        weekly_load=weekly_load,
        max_weekly_load=max_weekly_load,
        country_stats=country_stats,
        route_map_cities=route_map_cities,
        route_map_lines=route_map_lines
    )

@app.route("/add-flight", methods=["POST"])
def add_flight():

    try:
        # SECURITY FIX: validate flight fields and normalize them before query/insert usage.
        flight = safe_text(request.form["flight"].upper(), field_name="flight number", allow_empty=False, max_length=20, pattern=FLIGHT_NUMBER_PATTERN)
        departure = safe_text(request.form["departure"], field_name="departure", allow_empty=False, max_length=60)
        destination = safe_text(request.form["destination"], field_name="destination", allow_empty=False, max_length=60)
        gate = safe_text(request.form["gate"].upper(), field_name="gate", allow_empty=False, max_length=3, pattern=GATE_PATTERN)
        time = safe_datetime_local(request.form["time"], field_name="time")
    except ValueError:
        return redirect("/flights")

    status = "On Time"

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM flights WHERE flight_number = ?",
        (flight,)
    )

    if cursor.fetchone():
        conn.close()
        return redirect("/flights?error=flight_exists")

    cursor.execute("""
        INSERT INTO flights
        (flight_number, departure, destination, gate, time, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (flight, departure, destination, gate, time, status))

    conn.commit()
    conn.close()

    return redirect("/flights")


@app.route("/update-flight-status/<int:id>", methods=["POST"])
def update_flight_status(id):

    try:
        # SECURITY FIX: whitelist status values and sanitize redirect targets.
        status = safe_choice(request.form["status"], FLIGHT_STATUS_CHOICES, field_name="status")
    except ValueError:
        return redirect("/flights")

    next_page = safe_redirect_path(request.form.get("next", "/flights"), default="/flights")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE flights SET status=? WHERE id=?",
        (status, id)
    )
    conn.commit()
    conn.close()

    return redirect(next_page)

@app.route("/delete-flight/<int:id>", methods=["POST"])
def delete_flight(id):

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM flights WHERE id=?", (id,))

    conn.commit()
    conn.close()

    return redirect("/flights")

@app.route("/refresh-flights")
def refresh_flights():
    return redirect("/flights")

@app.route("/passengers")
def passengers():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        # SECURITY FIX: sanitize query filters before building static WHERE clauses.
        selected_flight_id = safe_id(request.args.get("flight", ""), field_name="flight", allow_empty=True)
        selected_name = safe_text(request.args.get("name", ""), field_name="name", allow_empty=True, max_length=60)
    except ValueError:
        selected_flight_id = None
        selected_name = ""

    selected_flight = str(selected_flight_id) if selected_flight_id else ""

    # flights list for dropdown
    cursor.execute("SELECT id, flight_number, departure, destination, gate FROM flights")
    flights = cursor.fetchall()

    # passenger table
    query = """
        SELECT passengers.id,
               passengers.name,
               passengers.passport,
               flights.flight_number,
               passengers.seat
        FROM passengers
        JOIN flights ON passengers.flight_id = flights.id
    """
    params = []
    conditions = []
    
    if selected_flight:
        conditions.append("flights.id = ?")
        params.append(selected_flight_id)
    
    if selected_name:
        conditions.append("passengers.name LIKE ? ESCAPE '\\'")
        params.append(safe_like_text(selected_name, field_name="name", max_length=60))
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    cursor.execute(query, params)
    passengers = cursor.fetchall()

    # seats already taken
    cursor.execute("SELECT seat, flight_id FROM passengers")
    taken_data = cursor.fetchall()

    conn.close()

    return render_template(
        "passengers.html",
        flights=flights,
        passengers=passengers,
        taken_data=taken_data,
        selected_flight=selected_flight,
        selected_name=selected_name
    )
    
    
@app.route("/add-passenger", methods=["POST"])
def add_passenger():

    try:
        # SECURITY FIX: validate passenger form fields before any passenger queries run.
        name = safe_text(request.form["name"], field_name="name", allow_empty=False, max_length=60)
        passport = safe_text(request.form["passport"], field_name="passport", allow_empty=False, max_length=8, pattern=PASSPORT_PATTERN)
        flight_id = safe_id(request.form["flight"], field_name="flight")
        seat = safe_text(request.form["seat"].upper(), field_name="seat", allow_empty=True, max_length=3, pattern=SEAT_PATTERN)
    except ValueError:
        return redirect("/passengers")
    
    if seat == "":
        return redirect(f"/passengers?flight={flight_id}&error=seat_required")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM passengers WHERE passport=?",
        (passport,)
    )

    if cursor.fetchone():
        conn.close()
        return redirect(f"/passengers?flight={flight_id}&error=wrong_passport")

    # limit passengers per flight
    cursor.execute(
        "SELECT COUNT(*) FROM passengers WHERE flight_id=?",
        (flight_id,)
    )
    count = cursor.fetchone()[0]

    if count >= 100:
        conn.close()
        return "Flight full (max 100 passengers)"

    # prevent duplicate seat
    cursor.execute(
        "SELECT * FROM passengers WHERE flight_id=? AND seat=?",
        (flight_id, seat)
    )

    if cursor.fetchone():
        conn.close()
        return "Seat already taken"

    cursor.execute("""
    INSERT INTO passengers(name,passport,flight_id,seat)
    VALUES(?,?,?,?)
    """,(name,passport,flight_id,seat))

    conn.commit()
    conn.close()

    return redirect(f"/passengers?flight={flight_id}")

@app.route("/delete-passenger/<int:id>", methods=["POST"])
def delete_passenger(id):

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM passengers WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    try:
        selected_flight_id = safe_id(request.form.get("flight", ""), field_name="flight", allow_empty=True)
    except ValueError:
        selected_flight_id = None

    if selected_flight_id:
        return redirect(f"/passengers?flight={selected_flight_id}")

    return redirect("/passengers")

@app.route("/baggage")
def baggage():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # SECURITY FIX: normalize baggage filters before they influence query conditions.
    filters = parse_baggage_filters(request.args)
    selected_flight_id = filters["selected_flight_id"]
    selected_date = filters["selected_date"]
    selected_end_date = filters["selected_end_date"]
    filter_type = filters["filter_type"]

    selected_flight = str(selected_flight_id) if selected_flight_id else ""
    filter_error = ""

    cursor.execute("SELECT id, name, flight_id FROM passengers")
    passengers = cursor.fetchall()

    cursor.execute("SELECT id, flight_number, departure, destination, gate FROM flights")
    flights = cursor.fetchall()

    query = """
        SELECT baggage.id,
               baggage.tag,
               passengers.name,
               flights.flight_number,
               baggage.weight,
               baggage.extra_weight,
               baggage.price,
               baggage.status,
               baggage.location,
               flights.time,
               flights.id
        FROM baggage
        JOIN passengers ON baggage.passenger_id = passengers.id
        JOIN flights ON baggage.flight_id = flights.id
    """
    params = []

    if selected_flight:
        query += " WHERE flights.id = ?"
        params.append(selected_flight_id)

    if selected_date:
        try:
            start_date_value, end_date_value = build_filter_date_params(
                selected_date,
                filter_type,
                selected_end_date,
            )
        except ValueError:
            filter_error = "End date must be after the start date."
        else:
            query += " AND" if params else " WHERE"
            query += " datetime(flights.time) >= datetime(?) AND datetime(flights.time) < datetime(?)"
            params.extend([start_date_value, end_date_value])

    query += " ORDER BY datetime(flights.time) ASC"
    cursor.execute(query, params)
    baggage = cursor.fetchall()

    conn.close()

    return render_template(
        "baggage.html",
        passengers=passengers,
        flights=flights,
        baggage=baggage,
        selected_flight=selected_flight,
        selected_date=selected_date,
        selected_end_date=selected_end_date,
        filter_type=filter_type,
        filter_error=filter_error,
        filter_summary="" if filter_error else build_filter_summary(filter_type, selected_date, selected_end_date)
    )
    
@app.route("/add-baggage", methods=["POST"])
def add_baggage():
    try:
        # SECURITY FIX: baggage input is validated centrally before any database access.
        tag = safe_text(request.form.get("tag", ""), field_name="tag", allow_empty=False, max_length=30, pattern=TAG_PATTERN).upper()
        passenger_id = safe_id(request.form.get("passenger_id", ""), field_name="passenger")
        flight_id = safe_id(request.form.get("flight_id", ""), field_name="flight")
        status = safe_choice(request.form.get("status", ""), BAGGAGE_STATUS_CHOICES, field_name="status")
    except ValueError:
        return redirect("/baggage?error=missing_fields")

    try:
        weight = float(request.form.get("weight", "").strip())
    except (ValueError, TypeError, AttributeError):
        return redirect("/baggage?error=invalid_weight")

    if weight <= 0 or weight > 43:
        return redirect("/baggage?error=invalid_weight")

    extra_weight = max(0, weight - 23)

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id FROM baggage WHERE tag=?", (tag,))
        if cursor.fetchone():
            return redirect("/baggage?error=tag_exists")

        cursor.execute(
            "SELECT * FROM baggage WHERE passenger_id = ? AND flight_id = ?",
            (passenger_id, flight_id)
        )
        if cursor.fetchone():
            return redirect("/baggage?error=baggage_duplicate")

        cursor.execute("SELECT departure, destination FROM flights WHERE id = ?", (flight_id,))
        flight_row = cursor.fetchone()
        if not flight_row:
            return redirect("/baggage?error=flight_not_found")

        price = extra_weight * 25
        location = flight_row[1] if status == "Arrived" else flight_row[0]

        cursor.execute("""
            INSERT INTO baggage
            (tag, passenger_id, flight_id, weight, extra_weight, price, status, location)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (tag, passenger_id, flight_id, weight, extra_weight, price, status, location))

        conn.commit()
    finally:
        conn.close()

    return redirect("/baggage")

@app.route("/delete-baggage/<int:id>", methods=["POST"])
def delete_baggage(id):

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM baggage WHERE id=?", (id,))

    conn.commit()
    conn.close()

    filters = parse_baggage_filters(request.form, default_filter_type="")
    params = build_baggage_redirect_params(
        filters["selected_flight_id"],
        filters["selected_date"],
        filters["selected_end_date"],
        filters["filter_type"],
    )

    if params:
        return redirect("/baggage?" + urlencode(params))

    return redirect("/baggage")


@app.route("/upload", methods=["GET","POST"])
def upload():
    if not current_user_is_admin():
        return redirect("/dashboard")

    if request.method == "POST":
        # SECURITY FIX: fetch files safely and validate presence before saving.
        passport = request.files.get("passport")
        cin = request.files.get("cin")

        passport_filename, passport_error = save_uploaded_file(
            passport,
            app.config["UPLOAD_FOLDER"],
            ALLOWED_UPLOAD_EXTENSIONS,
            ALLOWED_UPLOAD_MIME_TYPES,
            prefix="passport"
        )
        if passport_error:
            return passport_error

        cin_filename, cin_error = save_uploaded_file(
            cin,
            app.config["UPLOAD_FOLDER"],
            ALLOWED_UPLOAD_EXTENSIONS,
            ALLOWED_UPLOAD_MIME_TYPES,
            prefix="cin"
        )
        if cin_error:
            if passport_filename:
                passport_path = os.path.join(app.config["UPLOAD_FOLDER"], passport_filename)
                if os.path.exists(passport_path):
                    os.remove(passport_path)
            return cin_error

        return "File uploaded"

    return render_template("upload.html")

@app.route("/search-flights", methods=["POST"])
def search_flights():

    try:
        # SECURITY FIX: sanitize LIKE search terms and escape wildcards before querying.
        search_inputs = parse_search_fields(request.form)
    except ValueError:
        search_inputs = {
            "departure": "",
            "destination": "",
            "departure_like": "%",
            "destination_like": "%",
        }

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    query, params = build_flight_search_query(
        search_inputs["departure_like"],
        search_inputs["destination_like"],
    )
    cursor.execute(query, params)

    flights = cursor.fetchall()
    results = fetch_flight_search_results(cursor, flights)

    conn.close()

    return render_search_results(
        [] if len(results) == 0 else results,
        departure=search_inputs["departure"],
        destination=search_inputs["destination"],
    )

@app.route("/filter-flights", methods=["POST"])
def filter_flights():

    try:
        # SECURITY FIX: validate filter form values before they reach SQL or date logic.
        search_inputs = parse_search_fields(request.form)
        selected_date = safe_date_value(request.form["date"], field_name="date", allow_empty=True)
        selected_end_date = safe_date_value(request.form.get("end_date", ""), field_name="end date", allow_empty=True)
        filter_type = safe_choice(
            request.form["filter"],
            FILTER_TYPE_CHOICES,
            default=SEARCH_RESULTS_DEFAULT_FILTER_TYPE,
            field_name="filter",
        )
    except ValueError:
        return render_search_results([], filter_error="Invalid search filters.")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    query = FLIGHT_SEARCH_BASE_QUERY
    params = [
        search_inputs["departure_like"] or "%",
        search_inputs["destination_like"] or "%",
    ]

    if selected_date:
        try:
            start_date_value, end_date_value = build_filter_date_params(
                selected_date,
                filter_type,
                selected_end_date,
            )
        except ValueError:
            conn.close()
            return render_search_results(
                [],
                departure=search_inputs["departure"],
                destination=search_inputs["destination"],
                selected_date=selected_date,
                selected_end_date=selected_end_date,
                filter_type=filter_type,
                filter_error="End date must be after the start date.",
            )
        query, params = build_flight_search_query(
            search_inputs["departure_like"],
            search_inputs["destination_like"],
            start_date_value,
            end_date_value,
        )

    cursor.execute(query, params)

    flights = cursor.fetchall()
    results = fetch_flight_search_results(cursor, flights)

    conn.close()

    return render_search_results(
        results,
        departure=search_inputs["departure"],
        destination=search_inputs["destination"],
        selected_date=selected_date,
        selected_end_date=selected_end_date,
        filter_type=filter_type,
        filter_summary=build_filter_summary(filter_type, selected_date, selected_end_date),
    )
    
@app.route("/gates")
def gates():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT gate, flight_number, time, status
    FROM flights
    WHERE date(time) = date('now')
    ORDER BY gate
    """)

    rows = cursor.fetchall()
    conn.close()

    gates = {
        "A1": [],
        "A2": [],
        "A3": [],
        "A4": [],
        "B1": [],
        "B2": [],
        "B3": [],
        "C1": []
    }

    for gate, flight, time, status in rows:

        if gate in gates:
            gates[gate].append((flight, time, status))

    return render_template("gates.html", gates=gates)

@app.route("/delays")
def delays():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, flight_number, gate, time, status
    FROM flights
    WHERE status='Delayed'
    """)

    rows = cursor.fetchall()

    flights = []

    for row in rows:

        flight_id = row[0]
        flight = row[1]
        gate = row[2]
        time = row[3]
        status = row[4]

        delay_minutes = calculate_delay_minutes(time)

        flights.append((flight_id, flight, gate, time, status, delay_minutes))

    conn.close()

    return render_template("delays.html", flights=flights)

@app.route("/update-delay", methods=["POST"])
def update_delay():

    try:
        # SECURITY FIX: validate delay update fields before running the update query.
        flight_id = safe_id(request.form["id"], field_name="flight")
        new_time = safe_datetime_local(request.form["new_time"], field_name="time")
    except ValueError:
        return redirect("/delays")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    UPDATE flights
    SET time=?, status='Delayed'
    WHERE id=?
    """, (new_time, flight_id))

    conn.commit()
    conn.close()

    return redirect("/delays")

@app.route("/schedule")
def schedule():
    flights = fetch_current_month_flights()

    return render_template(
        "schedule.html",
        flights=flights,
        editable=False,
        page_title="Flight Schedule",
        page_kicker="Flight Schedule",
        page_description="Review the current monthly schedule across all flights in the active roster.",
        panel_title="Monthly Flight Schedule",
        panel_description="Scheduled flights for the current month in a read-only planning view."
    )

@app.route("/flight-status")
def flight_status():
    flights = fetch_current_month_flights()

    return render_template(
        "schedule.html",
        flights=flights,
        editable=True,
        page_title="Flight Status",
        page_kicker="Flight Status",
        page_description="Monitor the current monthly roster and update each flight status from the operations table.",
        panel_title="Monthly Flight Status",
        panel_description="Scheduled flights for the current month with direct status editing."
    )

@app.route("/logs")
def logs():
    if not current_user_is_admin():
        return redirect("/dashboard")

    try:
        with open("system.log","r") as f:
            logs = f.readlines()
    except:
        logs = ["No logs available"]

    return render_template("logs.html", logs=logs)

@app.route("/security")
def security():
    if not current_user_is_admin():
        return redirect("/dashboard")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM security_alerts")

    alerts = cursor.fetchall()

    conn.close()

    return render_template("security.html", alerts=alerts)


@app.route("/users")
def users():
    if not current_user_is_admin():
        return redirect("/dashboard")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, role, pfp FROM users")

    users = cursor.fetchall()

    conn.close()

    return render_template(
        "users.html",
        users=users,
        password_status=safe_query_message(request.args.get("password_status", ""), max_length=PASSWORD_STATUS_MAX_LENGTH),
        password_message=safe_query_message(request.args.get("password_message", ""), max_length=PASSWORD_MESSAGE_MAX_LENGTH)
    )


@app.route("/add-user", methods=["POST"])
def add_user():
    if not current_user_is_admin():
        return redirect("/dashboard")

    try:
        # SECURITY FIX: validate admin-created user data before insertion.
        username = safe_username(request.form["username"])
        role = safe_choice(request.form.get("role", "staff"), ROLE_CHOICES, default="staff", field_name="role")
    except ValueError:
        return redirect("/users")

    password = request.form["password"]
    pfp_file = request.files.get("pfp")
    pfp_filename = save_user_profile_image(pfp_file, username)

    conn = db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO users(username, password, role, name, email, phone, staff_id, department, pfp)
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (username, generate_password_hash(password), role, "", "", "", "", "", pfp_filename))
    conn.commit()
    conn.close()

    return redirect("/users")


@app.route("/update-user-pfp/<int:id>", methods=["POST"])
def update_user_pfp(id):
    if not current_user_is_admin():
        return redirect("/dashboard")

    pfp_file = request.files.get("pfp")

    conn = db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, pfp FROM users WHERE id=?", (id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return redirect("/users")

    pfp_filename = save_user_profile_image(pfp_file, user[0])

    if pfp_filename:
        if user[1]:
            old_path = os.path.join(USER_PFP_FOLDER, user[1])
            if os.path.exists(old_path):
                os.remove(old_path)

        cursor.execute("UPDATE users SET pfp=? WHERE id=?", (pfp_filename, id))
        conn.commit()

    conn.close()

    return redirect("/users")


@app.route("/change-user-password/<int:id>", methods=["POST"])
def change_user_password(id):
    if not current_user_is_admin():
        return redirect("/dashboard")

    new_password = request.form.get("new_password", "").strip()

    if not new_password:
        return build_user_password_redirect("error", "Password cannot be empty")

    conn = db()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id FROM users WHERE id=?", (id,))
        if not cursor.fetchone():
            return build_user_password_redirect("error", "User not found")

        cursor.execute(
            "UPDATE users SET password=? WHERE id=?",
            (generate_password_hash(new_password), id)
        )
        conn.commit()
    finally:
        conn.close()

    return build_user_password_redirect("success", "Password updated successfully")


@app.route("/delete-user/<int:id>", methods=["POST"])
def delete_user(id):
    if not current_user_is_admin():
        return redirect("/dashboard")

    conn = db()
    cursor = conn.cursor()
    cursor.execute("SELECT pfp FROM users WHERE id=?", (id,))
    user = cursor.fetchone()

    cursor.execute("DELETE FROM users WHERE id=?", (id,))
    conn.commit()
    conn.close()

    if user and user[0]:
        old_path = os.path.join(USER_PFP_FOLDER, user[0])
        if os.path.exists(old_path):
            os.remove(old_path)

    return redirect("/users")

@app.route("/monitoring")
def monitoring():
    if not current_user_is_admin():
        return redirect("/dashboard")

    cpu = psutil.cpu_percent()
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    return render_template(
        "monitoring.html",
        cpu=cpu,
        memory=memory,
        disk=disk
    )
    
    
@app.route("/seats")
def seats():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        # SECURITY FIX: sanitize seat page filters before adding them to a static query.
        selected_flight_id = safe_id(request.args.get("flight", ""), field_name="flight", allow_empty=True)
        selected_name = safe_text(request.args.get("name", ""), field_name="name", allow_empty=True, max_length=60)
    except ValueError:
        selected_flight_id = None
        selected_name = ""

    selected_flight = str(selected_flight_id) if selected_flight_id else ""

    cursor.execute("SELECT id, flight_number FROM flights")
    flights = cursor.fetchall()

    query = """
    SELECT passengers.id,
           passengers.name,
           passengers.passport,
           flights.flight_number,
           passengers.seat
    FROM passengers
    JOIN flights ON passengers.flight_id = flights.id
    """
    params = []
    conditions = []
    
    if selected_flight:
        conditions.append("flights.id = ?")
        params.append(selected_flight_id)
    
    if selected_name:
        conditions.append("passengers.name LIKE ? ESCAPE '\\'")
        params.append(safe_like_text(selected_name, field_name="name", max_length=60))
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    cursor.execute(query, params)
    passengers = cursor.fetchall()

    conn.close()

    return render_template(
        "seats.html",
        passengers=passengers,
        flights=flights,
        selected_flight=selected_flight,
        selected_name=selected_name
    )


if __name__ == "__main__":
    env = os.environ.get("FLASK_ENV", "development")

    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_RUN_PORT", 5000))
    debug = env == "development"

    app.config["SESSION_COOKIE_SECURE"] = not debug

    app.run(host=host, port=port, debug=debug)
