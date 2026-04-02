from flask import Flask, render_template, request, redirect, session
from flask_wtf import CSRFProtect
import sqlite3
import os
import psutil
import calendar
from datetime import date
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = "tunisair-operations-secret"
csrf = CSRFProtect(app)
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
USER_PFP_FOLDER = os.path.join("static", "uploads", "users")
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


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

    for column_name in ["name", "email", "phone", "staff_id", "department"]:
        if column_name not in columns:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {column_name} TEXT")
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
    if not file_storage or not file_storage.filename:
        return ""

    if not allowed_image(file_storage.filename):
        return ""

    safe_name = secure_filename(username or "user")
    extension = file_storage.filename.rsplit(".", 1)[1].lower()
    filename = f"{safe_name}_{int(datetime.now().timestamp())}.{extension}"
    os.makedirs(USER_PFP_FOLDER, exist_ok=True)
    file_storage.save(os.path.join(USER_PFP_FOLDER, filename))
    return filename


def add_months(value, months):
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def build_filter_summary(filter_type, selected_date, selected_end_date):
    if not selected_date:
        return ""

    if filter_type == "day":
        return f"Showing flights for {selected_date}"

    if selected_end_date:
        return f"Showing flights from {selected_date} to {selected_end_date}"

    return f"Showing flights from {selected_date} using the {filter_type} range"


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
    response.headers['Content-Security-Policy'] = "default-src 'self'"
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


@app.route("/")
def home():
    return redirect("/login")


@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

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


@app.route("/logout")
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
        profile_success=request.args.get("updated", "") == "1"
    )


@app.route("/update-profile", methods=["POST"])
def update_profile():
    user = get_current_user_profile()

    if not user:
        return redirect("/login")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").replace(" ", "").strip()
    staff_id = request.form.get("staff_id", "").strip()
    department = request.form.get("department", "").strip()
    requested_role = request.form.get("role", user["role"]).strip() or user["role"]
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

    if phone and (not phone.isdigit() or len(phone) != 8):
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
            scheduled = datetime.strptime(flight[5], "%Y-%m-%dT%H:%M")
        except ValueError:
            continue

        if scheduled >= now and len(upcoming_flights) < 6:
            upcoming_flights.append({
                "flight_number": flight[1],
                "departure": flight[2],
                "destination": flight[3],
                "gate": flight[4],
                "time": scheduled.strftime("%d %b %Y, %H:%M"),
                "status": flight[6],
            })

        route_key = f"{flight[2]} -> {flight[3]}"
        route_counts[route_key] = route_counts.get(route_key, 0) + 1
        gate_counts[flight[4]] = gate_counts.get(flight[4], 0) + 1

        date_key = scheduled.strftime("%d %b")
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
                scheduled = datetime.strptime(flight[5], "%Y-%m-%dT%H:%M")
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

    flight = request.form["flight"].strip()
    departure = request.form["departure"]
    destination = request.form["destination"]
    gate = request.form["gate"]
    time = request.form["time"]
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

    status = request.form["status"]
    next_page = request.form.get("next", "/flights").strip()

    if not next_page.startswith("/"):
        next_page = "/flights"

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE flights SET status=? WHERE id=?",
        (status, id)
    )
    conn.commit()
    conn.close()

    return redirect(next_page)

@app.route("/delete-flight/<int:id>")
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
    selected_flight = request.args.get("flight", "").strip()
    selected_name = request.args.get("name", "").strip()

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
        params.append(selected_flight)
    
    if selected_name:
        conditions.append("passengers.name LIKE ?")
        params.append(f"%{selected_name}%")
    
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

    name = request.form["name"]
    passport = request.form["passport"]
    flight_id = request.form["flight"]
    seat = request.form["seat"]
    
    if seat == "":
        return "You must select a seat"

    # passport validation
    if not passport.isdigit() or len(passport) != 8:
        return "Passport must contain exactly 8 digits"

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

@app.route("/delete-passenger/<int:id>")
def delete_passenger(id):

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM passengers WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    selected_flight = request.args.get("flight", "").strip()

    if selected_flight:
        return redirect(f"/passengers?flight={selected_flight}")

    return redirect("/passengers")

@app.route("/baggage")
def baggage():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    selected_flight = request.args.get("flight", "").strip()
    selected_date = request.args.get("date", "").strip()
    selected_end_date = request.args.get("end_date", "").strip()
    filter_type = request.args.get("filter", "day").strip() or "day"
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
        params.append(selected_flight)

    if selected_date:
        start_date = datetime.strptime(selected_date, "%Y-%m-%d")

        if filter_type == "day":
            end_date = start_date + timedelta(days=1)
        elif selected_end_date:
            end_date = datetime.strptime(selected_end_date, "%Y-%m-%d") + timedelta(days=1)
        elif filter_type == "week":
            end_date = start_date + timedelta(days=7)
        elif filter_type == "month":
            end_date = add_months(start_date, 1)
        else:
            end_date = add_months(start_date, 12)

        if end_date <= start_date:
            filter_error = "End date must be after the start date."
        else:
            query += " AND" if params else " WHERE"
            query += " datetime(flights.time) >= datetime(?) AND datetime(flights.time) < datetime(?)"
            params.extend([
                start_date.strftime("%Y-%m-%d"),
                end_date.strftime("%Y-%m-%d")
            ])

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
    tag = request.form.get("tag", "").strip()
    passenger_id = request.form.get("passenger_id", "").strip()
    flight_id = request.form.get("flight_id", "").strip()
    status = request.form.get("status", "").strip()

    if not tag or not passenger_id or not flight_id or not status:
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

@app.route("/delete-baggage/<int:id>")
def delete_baggage(id):

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM baggage WHERE id=?", (id,))

    conn.commit()
    conn.close()

    selected_flight = request.args.get("flight", "").strip()
    selected_date = request.args.get("date", "").strip()
    selected_end_date = request.args.get("end_date", "").strip()
    filter_type = request.args.get("filter", "").strip()

    params = []
    if selected_flight:
        params.append(f"flight={selected_flight}")
    if selected_date:
        params.append(f"date={selected_date}")
    if selected_end_date:
        params.append(f"end_date={selected_end_date}")
    if filter_type:
        params.append(f"filter={filter_type}")

    if params:
        return redirect("/baggage?" + "&".join(params))

    return redirect("/baggage")


@app.route("/upload", methods=["GET","POST"])
def upload():
    if not current_user_is_admin():
        return redirect("/dashboard")

    if request.method == "POST":

        passport = request.files["passport"]
        cin = request.files["cin"]

        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

        path = os.path.join(app.config["UPLOAD_FOLDER"], passport.filename)
        passport.save(path)

        path = os.path.join(app.config["UPLOAD_FOLDER"], cin.filename)
        cin.save(path)

        return "File uploaded"

    return render_template("upload.html")

@app.route("/search-flights", methods=["POST"])
def search_flights():

    departure = request.form["departure"]
    destination = request.form["destination"]

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, flight_number, departure, destination, gate, time, status
    FROM flights
    WHERE departure LIKE ?
    AND destination LIKE ?
    """, ("%"+departure+"%", "%"+destination+"%"))

    flights = cursor.fetchall()

    results = []

    for f in flights:

        flight_id = f[0]

        cursor.execute("""
        SELECT name, passport, seat
        FROM passengers
        WHERE flight_id=?
        """,(flight_id,))

        passengers = cursor.fetchall()

        cursor.execute("""
        SELECT tag, weight, location
        FROM baggage
        WHERE flight_id=?
        """,(flight_id,))

        baggage = cursor.fetchall()

        results.append({
            "flight":f,
            "passengers":passengers
        })

    conn.close()

    if len(results) == 0:
        return render_template(
        "search_results.html",
        results=[],
        departure=departure,
        destination=destination,
        selected_date="",
        selected_end_date="",
        filter_type="day",
        filter_error="",
        filter_summary=""
    )

    return render_template(
    "search_results.html",
    results=results,
    departure=departure,
    destination=destination,
    selected_date="",
    selected_end_date="",
    filter_type="day",
    filter_error="",
    filter_summary=""
)
@app.route("/filter-flights", methods=["POST"])
def filter_flights():

    departure = request.form["departure"]
    destination = request.form["destination"]
    selected_date = request.form["date"]
    selected_end_date = request.form.get("end_date", "")
    filter_type = request.form["filter"]

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    query = """
    SELECT id, flight_number, departure, destination, gate, time, status
    FROM flights
    WHERE departure LIKE ?
    AND destination LIKE ?
    """

    params = ["%"+departure+"%", "%"+destination+"%"]

    if selected_date:
        start_date = datetime.strptime(selected_date, "%Y-%m-%d")

        if filter_type == "day":
            end_date = start_date + timedelta(days=1)
        elif selected_end_date:
            end_date = datetime.strptime(selected_end_date, "%Y-%m-%d") + timedelta(days=1)
        elif filter_type == "week":
            end_date = start_date + timedelta(days=7)
        elif filter_type == "month":
            end_date = add_months(start_date, 1)
        else:
            end_date = add_months(start_date, 12)

        if end_date <= start_date:
            conn.close()
            return render_template(
                "search_results.html",
                results=[],
                departure=departure,
                destination=destination,
                selected_date=selected_date,
                selected_end_date=selected_end_date,
                filter_type=filter_type,
                filter_error="End date must be after the start date.",
                filter_summary=""
            )

        query += " AND datetime(time) >= datetime(?) AND datetime(time) < datetime(?)"
        params.extend([
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d")
        ])

    cursor.execute(query, params)

    flights = cursor.fetchall()

    results = []

    for f in flights:

        flight_id = f[0]

        cursor.execute("""
        SELECT name, passport, seat
        FROM passengers
        WHERE flight_id=?
        """,(flight_id,))

        passengers = cursor.fetchall()

        results.append({
            "flight":f,
            "passengers":passengers
        })

    conn.close()

    return render_template(
        "search_results.html",
        results=results,
        departure=departure,
        destination=destination,
        selected_date=selected_date,
        selected_end_date=selected_end_date,
        filter_type=filter_type,
        filter_error="",
        filter_summary=build_filter_summary(filter_type, selected_date, selected_end_date)
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

        delay_minutes = None

        # example logic (can be improved later)
        try:
            scheduled = datetime.strptime(time, "%Y-%m-%dT%H:%M")
            now = datetime.now()

            delay_minutes = int((now - scheduled).total_seconds() / 60)

            if delay_minutes < 0:
                delay_minutes = 0

        except:
            delay_minutes = None

        flights.append((flight_id, flight, gate, time, status, delay_minutes))

    conn.close()

    return render_template("delays.html", flights=flights)

@app.route("/update-delay", methods=["POST"])
def update_delay():

    flight_id = request.form["id"]
    new_time = request.form["new_time"]

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

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, flight_number, departure, destination, gate, time, status
    FROM flights
    WHERE strftime('%m', time) = strftime('%m', 'now')
    ORDER BY time
    """)

    flights = cursor.fetchall()

    conn.close()

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

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, flight_number, departure, destination, gate, time, status
    FROM flights
    WHERE strftime('%m', time) = strftime('%m', 'now')
    ORDER BY time
    """)

    flights = cursor.fetchall()

    conn.close()

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
        password_status=request.args.get("password_status", "").strip(),
        password_message=request.args.get("password_message", "").strip()
    )


@app.route("/add-user", methods=["POST"])
def add_user():
    if not current_user_is_admin():
        return redirect("/dashboard")

    username = request.form["username"]
    password = request.form["password"]
    role = request.form.get("role", "staff")
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
        return redirect("/users?password_status=error&password_message=Password%20cannot%20be%20empty")

    conn = db()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id FROM users WHERE id=?", (id,))
        if not cursor.fetchone():
            return redirect("/users?password_status=error&password_message=User%20not%20found")

        cursor.execute(
            "UPDATE users SET password=? WHERE id=?",
            (generate_password_hash(new_password), id)
        )
        conn.commit()
    finally:
        conn.close()

    return redirect("/users?password_status=success&password_message=Password%20updated%20successfully")


@app.route("/delete-user/<int:id>")
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
    selected_flight = request.args.get("flight", "").strip()
    selected_name = request.args.get("name", "").strip()

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
        params.append(selected_flight)
    
    if selected_name:
        conditions.append("passengers.name LIKE ?")
        params.append(f"%{selected_name}%")
    
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
    app.run(host="0.0.0.0", port=5000, debug=True)
