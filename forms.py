from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, Length, URL, Optional


class MessageForm(FlaskForm):
    """Form for adding/editing messages."""

    text = TextAreaField('text', validators=[DataRequired()])


class UserAddForm(FlaskForm):
    """Form for adding users."""

    username = StringField('Username', validators=[DataRequired()])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Length(min=6)])
    image_url = StringField('(Optional) Image URL')


class LoginForm(FlaskForm):
    """Login form."""

    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[Length(min=6)])

class UserProfileForm(FlaskForm):
    """Form to edit user profile"""

    username = StringField('Username')
    email = StringField('E-mail', validators=[Email()])
    image_url = StringField('Image URL', validators=[Optional()])
    header_image_url = StringField('Header image URL', validators=[Optional()])
    location = StringField('Location', validators=[Optional(), Length(max=50)])
    bio = TextAreaField('Bio', validators=[Length(max=1000)])
    private = BooleanField('Make account private')
    password = PasswordField('Password')

class UserProfileAdminForm(FlaskForm):
    """Form to edit user profile"""

    username = StringField('Username')
    email = StringField('E-mail', validators=[Email()])
    image_url = StringField('Image URL', validators=[Optional()])
    header_image_url = StringField('Header image URL', validators=[Optional()])
    location = StringField('Location', validators=[Optional(), Length(max=50)])
    bio = TextAreaField('Bio', validators=[Length(max=1000)])
    private = BooleanField('Make account private')
    admin = BooleanField('Make admin')
    
class PasswordResetForm(FlaskForm):
    """Form to change user password"""

    current_password = PasswordField("Enter your current password", validators=[DataRequired()])
    new_password = PasswordField("Enter your new password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm your new password", validators=[DataRequired(), Length(min=6)])
