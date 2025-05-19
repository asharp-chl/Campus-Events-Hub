from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, TimeField, SelectField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = SelectField('Remember Me', choices=[('yes', 'Yes'), ('no', 'No')], default='no')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class EventForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    time = TimeField('Time', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired(), Length(max=100)])
    category = SelectField('Category', choices=[
        ('workshop', 'Workshop'),
        ('seminar', 'Seminar'),
        ('party', 'Party'),
        ('sports', 'Sports'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    submit = SubmitField('Submit')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('New Password', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[EqualTo('password'), Optional()])
    submit = SubmitField('Update Profile')

class FeedbackForm(FlaskForm):
    rating = SelectField('Rating', choices=[(i, str(i)) for i in range(1, 6)], validators=[DataRequired()])
    comment = TextAreaField('Comment', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Submit Feedback')