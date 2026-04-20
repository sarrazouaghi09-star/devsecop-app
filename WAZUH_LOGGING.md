# Wazuh logging setup

The Flask app writes JSON security events to `APP_LOG_FILE`.

Default local path:

```text
system.log
```

Recommended Docker path:

```text
/app/logs/app-security.log
```

## Run the app with a mounted log directory

```bash
mkdir -p logs

docker run -d -p 5000:5000 \
  -e ADMIN_PASSWORD='YOUR_ADMIN_PASSWORD' \
  -e FLASK_RUN_HOST=0.0.0.0 \
  -e APP_LOG_FILE=/app/logs/app-security.log \
  -v "$(pwd)/database.db:/app/database.db" \
  -v "$(pwd)/logs:/app/logs" \
  --name devsecop-app \
  ghcr.io/sarrazouaghi09-star/devsecop-app:latest
```

The host will receive app logs at:

```text
./logs/app-security.log
```

## Wazuh agent config

Add this to the Wazuh agent `ossec.conf`.

If the Wazuh agent runs on the same host as Docker:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/absolute/path/to/airline-vulnerable-app/logs/app-security.log</location>
</localfile>
```

If the Wazuh agent is also a container, mount the same host `logs` directory into the Wazuh agent container and point `location` to that mounted path.

Restart the agent after editing:

```bash
sudo systemctl restart wazuh-agent
```

## Custom detection rules

Add these rules to the Wazuh manager:

```text
/var/ossec/etc/rules/local_rules.xml
```

```xml
<group name="airline_app,">
  <rule id="100500" level="3">
    <decoded_as>json</decoded_as>
    <field name="app">airline-vulnerable-app</field>
    <description>Airline app security event</description>
  </rule>

  <rule id="100501" level="8">
    <if_sid>100500</if_sid>
    <field name="event_type">login_failed</field>
    <description>Airline app failed login for $(username) from $(source_ip)</description>
  </rule>

  <rule id="100502" level="10">
    <if_sid>100500</if_sid>
    <field name="event_type">suspicious_input</field>
    <description>Airline app blocked suspicious input in $(field) from $(source_ip)</description>
  </rule>

  <rule id="100503" level="8">
    <if_sid>100500</if_sid>
    <field name="event_type">file_upload_rejected</field>
    <description>Airline app rejected file upload: $(reason)</description>
  </rule>

  <rule id="100504" level="10">
    <if_sid>100500</if_sid>
    <field name="event_type">unauthorized_admin_route|unauthorized_admin_action</field>
    <description>Airline app unauthorized admin access attempt to $(target_route)</description>
  </rule>

  <rule id="100505" level="7">
    <if_sid>100500</if_sid>
    <field name="event_type">user_password_changed|user_deleted|flight_deleted|passenger_deleted|baggage_deleted</field>
    <description>Airline app sensitive data/admin change: $(event_type)</description>
  </rule>
</group>
```

Restart the manager after editing:

```bash
sudo systemctl restart wazuh-manager
```

## Test detection

Generate a failed login:

```bash
curl -k -i -c cookies.txt https://YOUR-CLOUDFLARE-URL/login
```

Then try a bad password from the browser, or post through the UI.

Check the log:

```bash
tail -f logs/app-security.log
```

Example event:

```json
{"timestamp":"2026-04-20T13:13:16.927613+00:00","app":"airline-vulnerable-app","event_type":"login_failed","outcome":"failure","severity":"warning","source_ip":"127.0.0.1","method":"POST","path":"/login","user_agent":"Python-urllib/3.14","user_id":null,"username":"admin","reason":"bad_credentials"}
```

Test that Wazuh rules match:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste the JSON event into `wazuh-logtest`. It should match rule `100501`.
