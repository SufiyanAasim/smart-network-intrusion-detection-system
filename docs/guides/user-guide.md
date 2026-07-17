# User Guide

## Live Capture tab

1. Select the adapter that carries the traffic you want to inspect.
2. Review the **Capture scope — this device** notice. Whole-LAN capture needs
   SPAN/port mirroring, a TAP, or a gateway/router sensor.
3. Click **Start Capture**. Requires Npcap on Windows or raw-socket
   privileges on Linux/macOS.
4. Packets are classified as they arrive; the visible dashboard refreshes at a
   calmer configurable cadence (2.5 seconds by default), and the last 100 packets are kept
   in memory and shown in the tables/charts.
5. Click **Stop Capture** only to pause packet intake. It never prepares or
   downloads a report.
6. Select **Prepare report exports** when you explicitly want the current
   snapshot's **CSV**, **PDF**, and **Print report** controls.

## Upload Wireshark File tab

1. Upload a `.pcap`/`.pcapng` file (sample files: `data/pcaps/`).
2. The file is parsed, classified, and the report + CSV download appear.
3. Removing the uploaded file clears the session state.

## Model Logic tab

Shows the top-10 most important features for each model
(`rf_model.feature_importances_` / `dt_model.feature_importances_`).
Isolation Forest doesn't expose feature importances (it's unsupervised), so
it isn't shown here.

## History tab

Shows totals persisted to `data/history.db` and the most recent 200
detections across every session, live or uploaded — not just the last 100
packets kept in the live view.

The six summary metrics use a fixed card size for quick comparison. Viewer
sessions can inspect triage and recent history; Administrator sessions also see
complete-history exports and encrypted backup controls.

## Credits and About

Credits is a primary tab beside History. It contains contributor profile
images, responsibilities, email links, GitHub actions, dataset attribution, and
the technology list. Select **About this project** at the bottom of Credits for
the concise project dialog.

Notification preferences are available from **Notifications** beside Deploy,
not in the sidebar. Sound and browser notifications remain opt-in.

## Access and roles

The compact sidebar **Access** card always shows the active access level. Live
Capture also places the operational role badge in the title row directly above
**Stop Capture**. The full product hero is intentionally limited to **Credits**
and contains no redundant access badge. Select **Role permissions** for the
in-app permission matrix.

On the sign-in page, first select **Administrator** or **Viewer**. The selected
card opens the matching credential form; the server still verifies that the
authenticated account has that role, so the selector cannot elevate access.

- **Administrator** — monitoring and investigation plus complete-history
  CSV/Excel export and encrypted database backup.
- **Viewer** — monitoring, live/PCAP analysis, recent history, and triage;
  protected full-history exports remain read-only.
- **Local owner** — shown when authentication is disabled; the local session
  retains full backward-compatible access.

Configure separate accounts with `NIDS_AUTH_USERS` as documented in
`.env.example`. Password hashes are generated with `python src/nids/auth.py`;
plaintext passwords must never be stored in configuration. Local source runs
automatically load the repository-root `.env`; shell, Docker, and Render values
still take precedence.

When `NIDS_SIGNUP_ENABLED=true`, the authentication page exposes a separate
**Create account** screen. It creates Viewer accounts only and stores their
salted PBKDF2 hashes in `NIDS_AUTH_DB_PATH` (default `data/auth.db`). Keep public
sign-up disabled on internet-facing deployments; Administrators remain
configuration-managed.

## Reading the summary

- **SAFE** — 0% flagged as attack.
- **SUSPICIOUS** — under 20% flagged; monitor the listed IPs.
- **CRITICAL THREAT** — 20%+ flagged; shows the most likely attacker/victim IP,
  and (if configured) fires an alert — see [Configuration](../../README.md#configuration).

## Third model: Isolation Forest

If `models/iforest_model.pkl` exists (run `python scripts/train_models.py`
to generate it), a third **Isolation Forest** column appears alongside
RF/DT. It's trained only on normal traffic and flags statistical outliers,
so it can catch attack patterns the supervised models weren't trained on —
and disagreements between it and RF/DT are themselves informative.
