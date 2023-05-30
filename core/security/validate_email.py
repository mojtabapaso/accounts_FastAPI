import re

email_regex = r'^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$'


def is_valid_email_regex(email):
    return re.match(email_regex, email) is not None