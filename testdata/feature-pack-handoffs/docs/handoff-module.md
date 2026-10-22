# Handoff module

This module stores handoffs and checklist items through native user-scoped CRUD.
The complete route is authenticated and updates only the current user's row.
Export the two models, static/shift-desk.html and flows/complete-handoff.yaml.
The optional HANDOFF_WEBHOOK_URL reference is a name only; this app sends no requests.
