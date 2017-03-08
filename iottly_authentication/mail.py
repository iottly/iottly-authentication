from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from tornado import gen


def email(from_address, to, subject, text, html):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject.decode('utf-8')
    msg['From'] = from_address
    msg['To'] = ', '.join(to)

    plain_part = MIMEText(text.decode('utf-8'), 'plain')
    html_part = MIMEText(html.decode('utf-8'), 'html')

    msg.attach(plain_part)
    msg.attach(html_part)

    return msg

class MailService:
    def __init__(self, client_klass, host, port, user, password):
        self.client = client_klass()
        self.host = host
        self.port = port
        self.user = user
        self.password = password

    @gen.coroutine
    def send(self, from_address, to, subject, text, html):
        client = self.client
        yield client.connect(self.host, self.port)
        yield client.ehlo()
        yield client.starttls()
        yield client.login(self.user, self.password)

        msg = email(from_address, to, subject, text, html)

        yield client.sendmail(from_address, to, msg.as_string())
        yield client.quit()


class MockSMTPAsync:
    @gen.coroutine
    def connect(self, host, port):
        return

    @gen.coroutine
    def ehlo(self):
        return

    @gen.coroutine
    def starttls(self):
        return

    @gen.coroutine
    def login(self, user, password):
        return

    @gen.coroutine
    def sendmail(self, from_address, to, msg):
        return

    @gen.coroutine
    def quit(self):
        return
