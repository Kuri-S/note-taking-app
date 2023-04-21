package handler

import (
    "fmt"
    //"log"
    "time"
    //"strings"
    //"net/smtp"
    //"strconv"
	"database/sql"
    "html/template"
    "net/http"
	"crypto/rand"

    //"gopkg.in/gomail.v2" 
    //"github.com/robfig/cron"
	"golang.org/x/crypto/bcrypt"	
    "github.com/gorilla/mux" 
	"github.com/gorilla/sessions"
    "github.com/google/uuid"
	_ "github.com/go-sql-driver/mysql"
)

type Note struct {
    ID        int
    Title     string
    Content   string
    Archived  bool
    CreatedAt time.Time
    UpdatedAt time.Time
    DateAdded time.Time
    UserID    int
}

var (
    id              int
    storedPassword  string
    storedSalt      []byte
    store = sessions.NewCookieStore([]byte("O4WvQo+VGaw8t7+5C9xR3bdRJWGCvn98coyvoZtDe9Y="))
)


/*
// AddNoteToBasket adds a note to the user's basket
func AddNoteToBasket(w http.ResponseWriter, r *http.Request) {
    // Check if user is authenticated
    session, err := store.Get(r, "session-name")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Parse note ID from URL parameter
    vars := mux.Vars(r)
    noteID := vars["id"]

    // Open database connection
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()

    // Insert note into basket
    userID := session.Values["user_id"].(int)
    _, err = db.Exec("INSERT INTO basket (note_id, user_id, date_added) VALUES (?, ?, ?)", noteID, userID, time.Now())
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Redirect user to basket page
    http.Redirect(w, r, "/basket", http.StatusSeeOther)
}

// DeleteExpiredNotes deletes notes in the basket that were added more than 10 days ago
func DeleteExpiredNotes() {
    // Open database connection
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Get current time minus 10 days
    tenDaysAgo := time.Now().Add(-10 * 24 * time.Hour)

    // Delete expired notes
    _, err = db.Exec("DELETE FROM basket WHERE date_added < ?", tenDaysAgo)
    if err != nil {
        log.Fatal(err)
    }
}

// StartDeleteExpiredNotes starts a background task to delete expired notes every day
func StartDeleteExpiredNotes() {
    // Run DeleteExpiredNotes every day at midnight
    cronJob := cron.New()
    cronJob.AddFunc("@daily", DeleteExpiredNotes)
    cronJob.Start()
}
*/
func basketHandler(w http.ResponseWriter, r *http.Request) {
   // Check if user is authenticated
   session, err := store.Get(r, "session-name")
   if err != nil {
       http.Error(w, err.Error(), http.StatusInternalServerError)
       return
   }
   if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
       http.Redirect(w, r, "/login", http.StatusSeeOther)
       return
   }

   // Connect to database
   db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
   if err != nil {
       http.Error(w, err.Error(), http.StatusInternalServerError)
       return
   }
   defer db.Close()

   // Get user's notes
   user_id := session.Values["user_id"].(int) // Assumes user_id is stored in session
   rows, err := db.Query("SELECT id, title, content FROM basket WHERE user_id = ?", user_id)
   if err != nil {
       http.Error(w, err.Error(), http.StatusInternalServerError)
       return
   }
   defer rows.Close()

   // Display notes on page
   var notes []Note
   for rows.Next() {
       note := Note{}
       err = rows.Scan(&note.ID, &note.Title, &note.Content)
       if err != nil {
           http.Error(w, err.Error(), http.StatusInternalServerError)
           return
       }
       notes = append(notes, note)
   }
   if err = rows.Err(); err != nil {
       http.Error(w, err.Error(), http.StatusInternalServerError)
       return
   }

    // Render template with notes
    tmpl, err := template.ParseFiles("../templates/basket.html", "../templates/header.html", "../templates/footer.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.ExecuteTemplate(w, "basket", notes)
}

func AddNoteToBasket(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id := vars["id"]

    // Check if user is authenticated
    session, err := store.Get(r, "session-name")
    if err != nil {
        http.Error(w, "could not get session: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Open database connection
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, "could not connect to database: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()

    // Get note details
    var title, content string
    var userID int
    err = db.QueryRow("SELECT title, content, user_id FROM note WHERE id = ?", id).Scan(&title, &content, &userID)
    if err != nil {
        http.Error(w, "could not get note: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Insert note into basket
    _, err = db.Exec("INSERT INTO basket (note_id, user_id, date_added, content, title)git push -u origin main VALUES (?, ?, ?, ?, ?)", id, userID, time.Now(), content, title)
    if err != nil {
        http.Error(w, "could not insert note into basket: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Delete note from notes table
    _, err = db.Exec("DELETE FROM note WHERE id = ?", id)
    if err != nil {
        http.Error(w, "could not delete note: "+err.Error(), http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/basket", http.StatusSeeOther)
}



/*
func DeleteOldBasketNotes() {
    // Open database connection
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Get current time minus 30 days
    thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour)

    // Delete old notes
    _, err = db.Exec("DELETE FROM basket WHERE date_added < ?", thirtyDaysAgo)
    if err != nil {
        log.Fatal(err)
    }
}
*/







func changeEmail(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }

    // Get user ID from session
    session, err := store.Get(r, "session-name")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    userID, ok := session.Values["user_id"].(int)
    if !ok {
        http.Error(w, "User not authenticated", http.StatusUnauthorized)
        return
    }

    // Get current email and new email from form
    password := r.FormValue("password")
    newEmail := r.FormValue("new-email")

    // Check that password is not empty
    if password == "" {
        http.Error(w, "Password is required", http.StatusBadRequest)
        return
    }

    // Check that new email is not empty
    if newEmail == "" {
        http.Error(w, "New email is required", http.StatusBadRequest)
        return
    }

    // Connect to database
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()

    // Get current email and password hash from database
    var (
        currentEmail    string
        passwordHash    string
        salt            []byte
    )
    err = db.QueryRow("SELECT email, password_hash, salt FROM user_table WHERE id=?", userID).Scan(&currentEmail, &passwordHash, &salt)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Check that password matches
    saltedPassword := []byte(password + string(salt))
    err = bcrypt.CompareHashAndPassword([]byte(passwordHash), saltedPassword)
    if err != nil {
        http.Error(w, "Incorrect password", http.StatusUnauthorized)
        return
    }

    // Check that new email is not already in use
    var count int
    err = db.QueryRow("SELECT COUNT(*) FROM user_table WHERE email=?", newEmail).Scan(&count)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    if count > 0 {
        http.Error(w, "New email is already in use", http.StatusBadRequest)
        return
    }

    // Update email in database
    stmt, err := db.Prepare("UPDATE user_table SET email=? WHERE id=?")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer stmt.Close()

    _, err = stmt.Exec(newEmail, userID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Redirect to profile page
    http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func changePassword(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }

    newPassword := r.FormValue("new-password")
    confirmPassword := r.FormValue("confirm-password")

    // Check if new password and confirm password match
    if newPassword != confirmPassword {
        http.Error(w, "Passwords do not match", http.StatusBadRequest)
        return
    }

    // Connect to database
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()

    // Get current user ID from session
    session, err := store.Get(r, "session-name")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    userID := session.Values["user_id"].(int)

    // Hash new password with new salt
    newSalt := make([]byte, 16)
    _, err = rand.Read(newSalt)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword+string(newSalt)), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Update user password hash and salt in database
    update, err := db.Prepare("UPDATE user_table SET password_hash=?, salt=? WHERE id=?")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer update.Close()

    _, err = update.Exec(hashedPassword, newSalt, userID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Redirect user to home page
    http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func deleteAccount(w http.ResponseWriter, r *http.Request) {
    // Check if the request method is POST
    if r.Method != "POST" {
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }

    // Get the user ID from the session
    session, err := store.Get(r, "session-name")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    userID, ok := session.Values["user_id"].(int)
    if !ok {
        http.Error(w, "User ID not found in session", http.StatusInternalServerError)
        return
    }

    // Get the user's password and confirm_password from the request body
    password := r.FormValue("password")

    // Connect to the database
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()

    err = db.QueryRow("SELECT password_hash, salt FROM user_table WHERE id=?", userID).Scan(&storedPassword, &storedSalt)
    if err != nil {
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    // Compare password with stored hash
    saltedPassword := []byte(password + string(storedSalt))
    err = bcrypt.CompareHashAndPassword([]byte(storedPassword), saltedPassword)
    if err != nil {
        http.Error(w, "Invalidpassword", http.StatusUnauthorized)
        return
    }

    // Delete the user's account
    _, err = db.Exec("DELETE FROM user_table WHERE id=?", userID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Clear the session
    session.Options.MaxAge = -1
    err = session.Save(r, w)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Redirect the user to the login page
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func magicLogin(w http.ResponseWriter, r *http.Request) {
    // Parse email from request body
    email := r.FormValue("email")
    if email == "" {
        http.Error(w, "Email address is required", http.StatusBadRequest)
        return
    }

    token := uuid.New().String()

    // Store the token in the database
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()

    var username string
    err = db.QueryRow("SELECT username FROM user_table WHERE email = ?", email).Scan(&username)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    _, err = db.Exec("INSERT INTO magic_tokens (email, token) VALUES (?, ?)", email, token)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Send magic login link to user's email
    magicLink := fmt.Sprintf("http://%s/magic_login/%s", r.Host, token)
    err = printMagicLoginToTerminal( magicLink)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Redirect user to magic login page
    //http.Redirect(w, r, "/magic-login", http.StatusSeeOther)
}

func magicLoginAuth(w http.ResponseWriter, r *http.Request) {
    // Parse token from URL parameter
    vars := mux.Vars(r)
    token := vars["token"]
    if token == "" {
        http.Error(w, "Invalid magic login link", http.StatusBadRequest)
        return
    }

    // Retrieve the email associated with the token from the database
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()

    var email string
    err = db.QueryRow("SELECT email FROM magic_tokens WHERE token = ?", token).Scan(&email)
    if err != nil {
        http.Error(w, "Invalid magic login link", http.StatusBadRequest)
        return
    }

    var id int
    err = db.QueryRow("SELECT id FROM user_table WHERE email=?", email).Scan(&id)
    if err != nil {
        http.Error(w, "Invalid username", http.StatusUnauthorized)
        return
    }

   // Create session and store user ID and name
   session, _ := store.Get(r, "session-name")
   session.Values["authenticated"] = true
   session.Values["user_id"] = id // сохраняем ID пользователя в сессии
   session.Save(r, w)
   if err != nil {
       http.Error(w, err.Error(), http.StatusInternalServerError)
       return
   }

    // Delete the magic token from the database
    _, err = db.Exec("DELETE FROM magic_tokens WHERE token = ?", token)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

func printMagicLoginToTerminal(magicLink string) error {
    _, err := fmt.Println("Magic login link:", magicLink)
    if err != nil {
        return err
    }
    return nil
}
/*
func sendMagicLoginEmail(email, token string) error {
    body := fmt.Sprintf("Click this link to log in: http://example.com/login?token=%s", token)
    auth := smtp.PlainAuth("", "username", "password", "mail.example.com")
    err := smtp.SendMail("mail.example.com:587", auth, "from@example.com", []string{email}, []byte(body))
    if err != nil {
        return err
    }
    return nil
}
*/
func email_login_page(w http.ResponseWriter, r *http.Request){
	tmpl, err := template.ParseFiles("../templates/email_login.html")

	if err != nil{
		panic(err)
	}

	tmpl.ExecuteTemplate(w, "email_login", nil)

}

func account_page(w http.ResponseWriter, r *http.Request){
	tmpl, err := template.ParseFiles("../templates/account.html", "../templates/header.html", "../templates/footer.html")

	if err != nil{
		panic(err)
	}

	tmpl.ExecuteTemplate(w, "account", nil)

}

func logout(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session-name")

    delete(session.Values, "authenticated")
    session.Save(r, w)

    http.Redirect(w, r, "/", http.StatusFound)
}

func requireLogin(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session, err := store.Get(r, "session-name")
        if err != nil || session.Values["authenticated"] != true {
            http.Redirect(w, r, "/login", http.StatusFound)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func createUser(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }

    email := r.FormValue("email") 
    username := r.FormValue("username")
    password := r.FormValue("password")
    confirmPassword := r.FormValue("confirm_password")

    if password != confirmPassword {
        http.Error(w, "Passwords do not match", http.StatusBadRequest)
        return
    }
    
    // Generate salt
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password+string(salt)), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

	// Connect db
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()

	// Save username, salt and hashed password to db
    insert, err := db.Prepare("INSERT INTO user_table(email, username, password_hash, salt) VALUES (?, ?, ?, ?)")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer insert.Close()

    _, err = insert.Exec(email, username, hashedPassword, salt)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }

    username := r.FormValue("username")
    password := r.FormValue("password")

    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()
    /*
    var (
        id              int
        storedPassword  string
        storedSalt      []byte
    )
    */
    err = db.QueryRow("SELECT id, password_hash, salt FROM user_table WHERE username=?", username).Scan(&id, &storedPassword, &storedSalt)
    if err != nil {
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    // Compare password with stored hash
    saltedPassword := []byte(password + string(storedSalt))
    err = bcrypt.CompareHashAndPassword([]byte(storedPassword), saltedPassword)
    if err != nil {
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    // Create session and store user ID and name
    session, _ := store.Get(r, "session-name")
    session.Values["authenticated"] = true
    session.Values["user_id"] = id // сохраняем ID пользователя в сессии
    session.Save(r, w)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Redirect user to home page
    http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

func save_note(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "session-name")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Проверяем, аутентифицирован ли пользователь
    if _, ok := session.Values["authenticated"]; !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Получаем ID пользователя из сессии
    userID, ok := session.Values["user_id"].(int)
    if !ok {
        http.Error(w, "Invalid user ID", http.StatusInternalServerError)
        return
    }

    // Проверяем тип данных запроса
    if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
        http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
        return
    }

    // Получаем данные заметки из тела запроса
    title := r.FormValue("noteTitle")
    content := r.FormValue("noteContent")

    // Подключаемся к базе данных
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()

    // Вставляем данные заметки в базу данных
    stmt, err := db.Prepare("INSERT INTO note (user_id, title, content) VALUES (?, ?, ?)")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer stmt.Close()

    _, err = stmt.Exec(userID, title, content)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "notes", http.StatusSeeOther)
    w.WriteHeader(http.StatusCreated)
}

func index_page(w http.ResponseWriter, r *http.Request){
	session, err := store.Get(r, "session-name")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {

    tmpl, err := template.ParseFiles("../templates/index.html", "../templates/header.html", "../templates/footer.html" )

	if err != nil{
		panic(err)
	}

	tmpl.ExecuteTemplate(w, "index", nil)

    return
    }

    http.Redirect(w, r, "/crenote", http.StatusSeeOther)
}

func register_page(w http.ResponseWriter, r *http.Request){
	tmpl, err := template.ParseFiles("../templates/register.html", "../templates/header.html", "../templates/footer.html" )

	if err != nil{
		panic(err)
	}

	tmpl.ExecuteTemplate(w, "register", nil)
}

func login_page(w http.ResponseWriter, r *http.Request){
	tmpl, err := template.ParseFiles("../templates/login.html", "../templates/header.html", "../templates/footer.html" )

	if err != nil{
		panic(err)
	}

	tmpl.ExecuteTemplate(w, "login", nil)
}

func crenote_page(w http.ResponseWriter, r *http.Request){    
    tmpl, err := template.ParseFiles("../templates/crenote.html", "../templates/header.html", "../templates/footer.html" )

	if err != nil{
		panic(err)
	}

	tmpl.ExecuteTemplate(w, "crenote", nil)
}

func notes_page(w http.ResponseWriter, r *http.Request) {
   // Check if user is authenticated
   session, err := store.Get(r, "session-name")
   if err != nil {
       http.Error(w, err.Error(), http.StatusInternalServerError)
       return
   }
   if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
       http.Redirect(w, r, "/login", http.StatusSeeOther)
       return
   }

   // Connect to database
   db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
   if err != nil {
       http.Error(w, err.Error(), http.StatusInternalServerError)
       return
   }
   defer db.Close()

   // Get user's notes
   user_id := session.Values["user_id"].(int) // Assumes user_id is stored in session
   rows, err := db.Query("SELECT id, title, content FROM note WHERE user_id = ?", user_id)
   if err != nil {
       http.Error(w, err.Error(), http.StatusInternalServerError)
       return
   }
   defer rows.Close()

   // Display notes on page
   var notes []Note
   for rows.Next() {
       note := Note{}
       err = rows.Scan(&note.ID, &note.Title, &note.Content)
       if err != nil {
           http.Error(w, err.Error(), http.StatusInternalServerError)
           return
       }
       notes = append(notes, note)
   }
   if err = rows.Err(); err != nil {
       http.Error(w, err.Error(), http.StatusInternalServerError)
       return
   }

	// Render the notes page
    tmpl, err := template.ParseFiles("../templates/notes.html", "../templates/header.html", "../templates/footer.html" )

	if err != nil{
		panic(err)
	}

	tmpl.ExecuteTemplate(w, "notes", notes)
}

func InOut(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session-name")

    // Проверяем, аутентифицирован ли пользователь
    if _, ok := session.Values["authenticated"]; !ok {
    // Если пользователь не аутентифицирован, перенаправляем на страницу входа
    http.Redirect(w, r, "/login", http.StatusFound)
        return
    }

    // Если пользователь аутентифицирован, перенаправляем на страницу выхода
    http.Redirect(w, r, "/logout", http.StatusFound)
}

func note_page(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)

    // Check if user is authenticated
    session, err := store.Get(r, "session-name")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()

    userID := session.Values["user_id"].(int) // Получаем ID пользователя из сессии

    row := db.QueryRow("SELECT id, title, content FROM note WHERE id = ? AND user_id = ?", vars["id"], userID)

    var note Note
    err = row.Scan(&note.ID, &note.Title, &note.Content)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    tmpl, err := template.ParseFiles("../templates/note.html", "../templates/header.html", "../templates/footer.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    tmpl.ExecuteTemplate(w, "note", note)
}

func deleteNote(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id := vars["id"]

    // Check if user is authenticated
    session, err := store.Get(r, "session-name")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Delete note from database
    db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer db.Close()

    _, err = db.Exec("DELETE FROM note WHERE id = ?", id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

func editNote(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Parse note ID from URL parameter
	vars := mux.Vars(r)
	noteID := vars["id"]

	// Open database connection
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/Note_db")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Retrieve note from database
	row := db.QueryRow("SELECT id, user_id, title, content FROM note WHERE id = ?", noteID)
	var note Note
	err = row.Scan(&note.ID, &note.UserID, &note.Title, &note.Content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if user has permission to edit this note
	userID := session.Values["user_id"].(int)
	if note.UserID != userID {
		http.Error(w, "You do not have permission to edit this note", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodGet {
		// Render edit note page
		tmpl, err := template.ParseFiles("../templates/edit-note.html", "../templates/header.html", "../templates/footer.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl.ExecuteTemplate(w, "edit-note", note)
	} else if r.Method == http.MethodPost {
		// Update note in database
		title := r.FormValue("title")
		content := r.FormValue("content")
		_, err := db.Exec("UPDATE note SET title=?, content=? WHERE id=?", title, content, noteID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/note/%s", noteID), http.StatusSeeOther)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func handleFunc(){
    rtr := mux.NewRouter()
    rtr.HandleFunc("/", index_page).Methods("GET")
    rtr.Handle("/logout", requireLogin(http.HandlerFunc(logout))).Methods("GET")
    rtr.Handle("/crenote", requireLogin(http.HandlerFunc(crenote_page))).Methods("GET")
	rtr.HandleFunc("/save_note", save_note).Methods("POST")
	rtr.HandleFunc("/login", login_page).Methods("GET")
    rtr.HandleFunc("/inout", InOut).Methods("GET")
	rtr.HandleFunc("/loginuser", login).Methods("POST")
	rtr.HandleFunc("/register/", register_page).Methods("GET")
	rtr.HandleFunc("/createuser", createUser).Methods("POST")
    rtr.HandleFunc("/notes", notes_page).Methods("GET")
    rtr.HandleFunc("/note/{id}", note_page).Methods("GET")
    rtr.HandleFunc("/note/{id}/edit", editNote).Methods("GET", "POST")
    //rtr.HandleFunc("/note/{id}/delete", deleteNote).Methods("POST")
    rtr.Handle("/account", requireLogin(http.HandlerFunc(account_page))).Methods("GET", "POST")
    rtr.HandleFunc("/magiclogin", magicLogin).Methods("POST")
    rtr.HandleFunc("/magic-login", email_login_page).Methods("GET")
    rtr.HandleFunc("/magic_login/{token}", magicLoginAuth).Methods("GET", "POST")
    rtr.HandleFunc("/change-email", changeEmail).Methods("POST")
    rtr.HandleFunc("/change-password", changePassword).Methods("POST")
    rtr.HandleFunc("/delete-account", deleteAccount).Methods("POST")

    rtr.HandleFunc("/basket", basketHandler).Methods("GET")
    //rtr.HandleFunc("/note/{id}/delete", AddNoteToBasket).Methods("POST")
    rtr.HandleFunc("/note/{id}/delete", AddNoteToBasket).Methods("POST", "GET")

    http.Handle("/", rtr)
    fs := http.FileServer(http.Dir("static"))
    http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.ListenAndServe(":8080", nil)
}

func main(){
	handleFunc()
}