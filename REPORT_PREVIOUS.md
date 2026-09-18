# Secure Vault: Encrypted Password Manager
# Ramanpreet kaur
# GH1035103

## 1. Introduction

Secure Vault is a web-based password manager developed with Python and Flask. The application allows a user to create an account, log in with a master password, store website credentials securely, generate strong passwords, and manage saved entries through a browser interface.

The main purpose of the project is to demonstrate secure web application development. Sensitive vault information is encrypted before it is stored in the database, while the master password is stored only as a one-way hash.

## 2. Objectives

The objectives of this project are:

- Create a user registration and authentication system.
- Store credentials in a SQLite database.
- Encrypt sensitive credential data before database storage.
- Hash and salt user master passwords.
- Provide add, view, update, and delete functionality.
- Include a password generator.
- Protect forms against CSRF attacks.
- Use parameterized SQL queries to reduce SQL injection risk.
- Provide a simple and responsive web interface.

## 3. Technologies Used

- **Programming language:** Python
- **Web framework:** Flask
- **Database:** SQLite
- **Encryption:** `cryptography` Fernet
- **Key derivation:** PBKDF2-HMAC with SHA-256
- **Password hashing:** Werkzeug password hashing
- **Frontend:** HTML, CSS, JavaScript, and Jinja templates
- **Development environment:** Visual Studio Code

## 4. System Design

The application uses Flask routes to handle browser requests. SQLite stores two main types of records:

### Users table

- User ID
- Username
- Hashed master password
- Encryption salt

### Vault entries table

- Entry ID
- User ID
- Encrypted credential data

The website, username, and password for each vault entry are combined into JSON and encrypted before being stored in the `encrypted_data` column.

## 5. Security Implementation

### Master password protection

The master password is never stored directly. Flask/Werkzeug creates a salted password hash. During login, the submitted password is checked against the stored hash.

### Credential encryption

The application creates an encryption key from the user's master password and a unique salt using PBKDF2-HMAC. Fernet then encrypts the credential data before it is inserted into SQLite.

### CSRF protection

Forms contain a random CSRF token stored in the user's session. POST requests verify the submitted token before changing data.

### SQL injection protection

Database values are passed as parameters using SQLite placeholders such as `?`. User input is never joined directly into SQL statements.

### Session protection

After successful login, the application creates a random session identifier. The encryption key is kept server-side in memory rather than being placed directly in the browser session cookie.

## 6. Main Features

### Registration and login

The user creates an account with a username and master password. The user must log in before accessing the vault.

### Add credential

The user can save a website name, username, and password. The password can be generated using the Generate button.

### View and search credentials

After login, the dashboard displays saved websites and usernames. Password values are hidden in the list, and the search box filters entries by website or username.

### Update credential

The Edit action loads an existing credential into a form. The user can change any field and save the updated encrypted record.

### Delete credential

The Delete action removes the selected entry after confirmation.

### Logout

Logout clears the active session and removes the server-side encryption key from memory.

## 7. How to Run the Application

From the project folder, run:

```powershell
$env:SECRET_KEY = "use-a-long-random-secret-value"
.\myvenv\Scripts\python.exe .\myvenv\app.py
```

Open the following address in a browser:

```text
http://127.0.0.1:5000/register
```

Create an account, log in, and use the dashboard to add and manage credentials.

## 8. Testing

The application was tested using Python's Flask test client. The test workflow checked:

1. User registration.
2. Login with the master password.
3. Adding a credential.
4. Confirming the plaintext password was not present in the database value.
5. Updating a credential.
6. Deleting a credential.
7. CSRF-protected form submission.

The complete registration, login, encryption, and CRUD workflow completed successfully.

## 9. Limitations

This project is intended for education and demonstration. It is not ready for storing important real-world passwords without further hardening. The current version should be improved with HTTPS, secure production session storage, rate limiting, stronger account recovery controls, encrypted backups, and security auditing.

The server-side encryption key is held in memory. Restarting the Flask server ends active sessions, so users must log in again.

## 10. Future Enhancements

- Add email-based account recovery.
- Add password strength scoring.
- Add password history and expiry reminders.
- Add secure sharing between approved users.
- Add automated security tests.
- Deploy with HTTPS and a production WSGI server.
- Move server-side sessions to a secure session store.

## 11. Conclusion

Secure Vault demonstrates how a Flask application can combine authentication, password hashing, encryption, database storage, and secure web forms. The project meets the main requirements of an encrypted password manager while remaining small enough to understand and extend as a beginner Python project.
