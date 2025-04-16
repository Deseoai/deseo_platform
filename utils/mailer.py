from flask_mail import Mail, Message
from flask import current_app, render_template
from threading import Thread

mail = Mail()

def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
            print(f"E-Mail erfolgreich an {msg.recipients} gesendet.")
        except Exception as e:
            print(f"Fehler beim Senden der E-Mail an {msg.recipients}: {e}")

def send_email(subject, recipients, template, **kwargs):
    """
    Sendet eine HTML-E-Mail unter Verwendung eines Templates.
    """
    app = current_app._get_current_object()
    sender = app.config['MAIL_DEFAULT_SENDER']
    if isinstance(recipients, str):
        recipients = [recipients]

    msg = Message(subject, sender=sender, recipients=recipients)
    # HTML aus Template rendern
    try:
        msg.html = render_template(template + '.html', **kwargs)
    except Exception as e:
        print(f"Fehler beim Rendern des Templates '{template}': {e}")
        return

    # Asynchron senden
    Thread(target=send_async_email, args=[app, msg]).start()

def send_password_reset_email(user, token):
    """
    Beispiel für Passwort-Reset-E-Mail-Versand.
    user-Objekt oder user-Dict braucht user.email.
    """
    if not user.email:
        print(f"Kein E-Mail beim Benutzer {user.username} für Passwort-Reset.")
        return
    subject = "Password Reset for Deseo Platform"
    send_email(
        subject=subject,
        recipients=[user.email],
        template="email_templates/reset_password_email",
        user=user,
        token=token
    )
