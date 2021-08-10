import unittest
from app.models import User, AnonymousUser, Permission

class UserModelTestCase(unittest.TestCase):
    def setUp(self):
        self.user = User(password='cat')

    def test_password_setter(self):
        self.assertTrue(self.user.password_hash is not None)

    def test_no_password_verification(self):
        with self.assertRaises(AttributeError):
            self.user.password

    def test_password_verification(self):
        self.assertTrue(self.user.verify_password('cat'))
        self.assertFalse(self.user.verify_password('dog'))

    def test_password_salts_are_random(self):
        user2 = User(password='cat')
        self.assertTrue(self.user.password_hash != user2.password_hash)

    def test_user_role(self):
        u = User(email='jan@flaskb.pl', password='kot')
        self.assertTrue(u.can(Permission.FOLLOW))
        self.assertTrue(u.can(Permission.COMMENT))
        self.assertTrue(u.can(Permission.WRITE))
        self.assertFalse(u.can(Permission.MODERATE))
        self.assertFalse(u.can(Permission.ADMIN))

    def test_anonymous_user(self):
        u = AnonymousUser()
        self.assertFalse(u.can(Permission.FOLLOW))
        self.assertFalse(u.can(Permission.COMMENT))
        self.assertFalse(u.can(Permission.WRITE))
        self.assertFalse(u.can(Permission.MODERATE))
        self.assertFalse(u.can(Permission.ADMIN))