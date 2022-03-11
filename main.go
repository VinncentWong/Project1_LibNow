package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var router *gin.Engine
var db *gorm.DB

func main() {
	err := InitDB()
	if err != nil {
		fmt.Println("Error when init database")
		return
	}
	router = gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowCredentials = true
	config.AddAllowHeaders("authorization")
	router.Use(cors.New(config))
	InitRouter()
	router.GET("/user/login", PostTesti)
	router.Run()
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}

func CORS() gin.HandlerFunc {
	// TO allow CORS
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func PostTesti(c *gin.Context) {
	c.JSON(200, gin.H{
		"success ": true,
	})
}

// Auth disini
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.Request.Header.Get("Authorization")
		header = header[len("Bearer "):]
		token, err := jwt.Parse(header, func(t *jwt.Token) (interface{}, error) {
			return []byte("passwordBuatSigningUser"), nil
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "JWT validation error.",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("id", claims["id"])
			c.Next()
			return
		} else {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": "JWT invalid.",
				"error":   err.Error(),
			})
			c.Abort()
			return
		}
	}
}

//Init disini

func InitDB() error {
	_db, err := gorm.Open(mysql.Open("root:@tcp(127.0.0.1:3306)/project1_libnow?parseTime=true"), &gorm.Config{})
	if err != nil {
		return err
	}
	db = _db
	err = db.AutoMigrate(&User{}, &UserConfirm{}, &BookLend{}, &Payment{}, &ReturnBookList{}, &TempUserConfirm{}, &Admin{}, &Book{}, &AdminLowVersion{}, &AdminConfirm{}, &BookLendAdmin{}, &UserConfirmAdmin{})
	if err != nil {
		return err
	}
	return nil
}

func InitRouter() {
	router.POST("/user/signup", PostSignupHandler)
	router.GET("/user/login", PostLoginHandler)
	router.GET("/user/libraryinfo", GetLibraryInfoHandler)
	router.GET("/user/getbookinfo", GetBookInfoHandler)
	router.POST("/user/request", AuthMiddleware(), PostRequestHandler)
	router.GET("/user/requestinfo/:username", AuthMiddleware(), GetConfirmFromAdminHandler)
	router.POST("/user/returnbook", AuthMiddleware(), ReturnBookHandler)
	router.GET("/user/getlistlendbook/:id", AuthMiddleware(), GetListLendBook)
	router.GET("/user/extendreturnbook/:id", AuthMiddleware(), PostExtendBookHandler)

	router.POST("/admin/signup", PostSignupHandlerAdmin)
	router.POST("/admin/login", PostLoginHandlerAdmin)
	router.POST("/admin/addbook", AuthMiddleware(), PostAddBookHandler)
	router.PATCH("/admin/editbook/:id", AuthMiddleware(), PatchEditBookHandler)
	router.DELETE("/admin/deletebook/:id", AuthMiddleware(), DeleteBookHandler)
	router.GET("/admin/profile/:id", AuthMiddleware(), GetProfileHandler)
	router.GET("/admin/getrequest/:libraryname", AuthMiddleware(), GetRequestHandler)
	router.POST("/admin/confirm", AuthMiddleware(), PostConfirmHandler)
	router.POST("/admin/payment", AuthMiddleware(), PostPaymentHandler)
}

// Struct disini

type Admin struct {
	ID            uint   `gorm:"primarykey"`
	Email         string `gorm:"email"`
	Password      string `gorm:"password"`
	LibraryName   string `gorm:"libraryname"`
	Province      string `gorm:"province"`
	City          string `gorm:"city"`
	District      string `gorm:"district"`
	Neighborhoods string `gorm:"neighborhoods"`
	Address       string `gorm:"address"`
	PhoneNumber   string `gorm:"phonenumber"`
	TimeOpenClose string `json:"time"`
}

type User struct {
	ID                 uint   `gorm:"primarykey"`
	Username           string `json:"username"`
	EmailOrPhoneNumber string `json:"emailorphonenumber"`
	Password           string `json:"password"`
}

type AdminLowVersion struct {
	ID          uint   `gorm:"primarykey"`
	LibraryName string `gorm:"libraryname"`
	Province    string `gorm:"province"`
	City        string `gorm:"city"`
	Address     string `gorm:"address"`
	PhoneNumber string `gorm:"phonenumber"`
}

type Login struct {
	ID       uint   `gorm:"primarykey"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Book struct {
	ID                uint   `gorm:"primarykey"`
	BookName          string `gorm:"bookname"`
	Synopsis          string `json:"synopsis"`
	Author            string `json:"author"`
	Stock             uint   `json:"stock"`
	ISBN              string `json:"isbn"`
	AdminLowVersion   AdminLowVersion
	AdminLowVersionID uint
}

type AdminConfirm struct {
	ID              uint `gorm:"primarykey"`
	BookLendAdmin   BookLendAdmin
	BookLendAdminID uint
	Accept          string `json:"confirm"`
	GetBook         time.Time
	ReturnBook      time.Time
	Token           string
}

type BookLendAdmin struct {
	ID                 uint   `gorm:"primarykey"`
	LibraryName        string `json:"libraryname"`
	BookName           string `json:"bookname"`
	Author             string `json:"author"`
	UserConfirmAdmin   UserConfirmAdmin
	UserConfirmAdminID uint
}

type UserConfirm struct {
	ID          uint   `gorm:"primarykey"`
	UserName    string `json:"username"`
	PhoneNumber string `json:"phonenumber"`
	Address     string `json:"address"`
}

type BookLend struct {
	ID            uint   `gorm:"primarykey"`
	LibraryName   string `json:"libraryname"`
	BookName      string `json:"bookname"`
	Author        string `json:"author"`
	UserConfirm   UserConfirm
	UserConfirmID uint
}

type Payment struct {
	ID          uint   `gorm:"primarykey"`
	LibraryName string `json:"libraryname"`
	Price       uint   `json:"price"`
}

type ReturnBookList struct {
	ID                uint   `gorm:"primarykey"`
	LibraryName       string `json:"libraryname"`
	BookName          string `json:"bookname"`
	Author            string `json:"author"`
	TempUserConfirm   TempUserConfirm
	TempUserConfirmID uint
	Price             uint
}

type TempUserConfirm struct {
	ID          uint   `gorm:"primarykey"`
	UserName    string `json:"username"`
	PhoneNumber string `json:"phonenumber"`
	Address     string `json:"address"`
}

type UserConfirmAdmin struct {
	ID          uint   `gorm:"primarykey"`
	UserName    string `json:"username"`
	PhoneNumber string `json:"phonenumber"`
	Address     string `json:"address"`
}

// Handler disini

func PostSignupHandler(c *gin.Context) {
	var bodyUser User

	err := c.BindJSON(&bodyUser)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": err.Error(),
			"success : ": false,
		})
		return
	}
	if strings.Contains(bodyUser.EmailOrPhoneNumber, "!") || strings.Contains(bodyUser.EmailOrPhoneNumber, "#") || strings.Contains(bodyUser.EmailOrPhoneNumber, "$") || strings.Contains(bodyUser.EmailOrPhoneNumber, "%") || strings.Contains(bodyUser.EmailOrPhoneNumber, "^") || strings.Contains(bodyUser.EmailOrPhoneNumber, "&") || strings.Contains(bodyUser.EmailOrPhoneNumber, "*") || strings.Contains(bodyUser.EmailOrPhoneNumber, "(") || strings.Contains(bodyUser.EmailOrPhoneNumber, "\"") || strings.Contains(bodyUser.EmailOrPhoneNumber, "~") || strings.Contains(bodyUser.EmailOrPhoneNumber, "+") || strings.Contains(bodyUser.EmailOrPhoneNumber, "=") || strings.Contains(bodyUser.EmailOrPhoneNumber, "{") || strings.Contains(bodyUser.EmailOrPhoneNumber, "}") || strings.Contains(bodyUser.EmailOrPhoneNumber, "|") || strings.Contains(bodyUser.EmailOrPhoneNumber, ":") || strings.Contains(bodyUser.EmailOrPhoneNumber, ";") || strings.Contains(bodyUser.EmailOrPhoneNumber, "<") || strings.Contains(bodyUser.EmailOrPhoneNumber, ">") || strings.Contains(bodyUser.EmailOrPhoneNumber, ",") || strings.Contains(bodyUser.EmailOrPhoneNumber, "?") || strings.Contains(bodyUser.EmailOrPhoneNumber, "/") {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "Email only can contain some symbols(_,@), numbers, or letters !",
			"success : ": false,
		})
		return
	}
	if len(bodyUser.Password) < 8 || len(bodyUser.Password) > 16 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "Password length must be between 8-16 !",
			"success : ": false,
		})
		return
	}
	if strings.Contains(bodyUser.Password, "!") || strings.Contains(bodyUser.Password, "@") || strings.Contains(bodyUser.Password, "#") || strings.Contains(bodyUser.Password, "$") || strings.Contains(bodyUser.Password, "%") || strings.Contains(bodyUser.Password, "^") || strings.Contains(bodyUser.Password, "&") || strings.Contains(bodyUser.Password, "*") || strings.Contains(bodyUser.Password, "(") || strings.Contains(bodyUser.Password, "\"") || strings.Contains(bodyUser.Password, "~") || strings.Contains(bodyUser.Password, "+") || strings.Contains(bodyUser.Password, "=") || strings.Contains(bodyUser.Password, "{") || strings.Contains(bodyUser.Password, "}") || strings.Contains(bodyUser.Password, "|") || strings.Contains(bodyUser.Password, ":") || strings.Contains(bodyUser.Password, ";") || strings.Contains(bodyUser.Password, "<") || strings.Contains(bodyUser.Password, ">") || strings.Contains(bodyUser.Password, ",") || strings.Contains(bodyUser.Password, ".") || strings.Contains(bodyUser.Password, "?") || strings.Contains(bodyUser.Password, "/") {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "Password only can contain some symbols(-,_), numbers, or letters !",
			"success : ": false,
		})
		return
	}
	user := User{
		ID:                 bodyUser.ID,
		EmailOrPhoneNumber: bodyUser.EmailOrPhoneNumber,
		Password:           bodyUser.Password,
		Username:           bodyUser.Username,
	}
	result := db.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Registration succesfully !",
		"success : ": true,
		"data : ": gin.H{
			"username : ":           user.Username,
			"email/phone number : ": user.EmailOrPhoneNumber,
		},
	})
}

func PostLoginHandler(c *gin.Context) {
	var bodyLogin User

	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "POST")

	err := c.BindJSON(&bodyLogin)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": err.Error(),
			"success : ": false,
		})
		return
	}
	var user User
	result := db.Where("email_or_phone_number = ?", bodyLogin.EmailOrPhoneNumber).Find(&user)
	// ? nanti akan diisi sama bodyLogin.EmailOrPhoneNumber
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	if user.Password == bodyLogin.Password {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":  user.ID,
			"exp": time.Now().Add(time.Hour * 24 * 14).Unix(),
		})
		tokenString, err := token.SignedString([]byte("passwordBuatSigningUser"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "Error when generating the token.",
				"error":   err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message : ": "Success Login !",
			"Token : ":   tokenString,
			"success : ": true,
		})
		return
	} else {
		c.JSON(http.StatusForbidden, gin.H{
			"message : ": "Wrong email or password !",
			"success : ": false,
		})
		return
	}
}

func GetLibraryInfoHandler(c *gin.Context) {
	var getAdmin []Admin

	result := db.Find(&getAdmin)
	// Find akan mencari data dari type data yang ada pada variabel tersebut

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}

	var tempAdmin []gin.H
	for _, value := range getAdmin {
		tempAdmin = append(tempAdmin, gin.H{
			"libraryname : ":  value.LibraryName,
			"province : ":     value.Province,
			"city : ":         value.City,
			"district : ":     value.District,
			"neigborhoods : ": value.Neighborhoods,
			"phonenumber : ":  value.PhoneNumber,
			"open - close":    value.TimeOpenClose,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Successfully get the data !",
		"data : ":    tempAdmin,
	})
}

func GetBookInfoHandler(c *gin.Context) {
	author, isAuthorExist := c.GetQuery("author")
	bookName, isBookNameExist := c.GetQuery("bookname")

	if !isAuthorExist && !isBookNameExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage : ": "Can't find author or bookname !",
			"success : ":  false,
		})
		return
	}
	// pakai c.Query kalau tidak wajib 2 2 , pakai getQuery kalau wajib 2 2
	var book []Book
	book = append(book, Book{
		Author:   author,
		BookName: bookName,
	})
	result := db
	if isAuthorExist && isBookNameExist {
		result := db.Where("author = ?", author).Where("book_name = ?", bookName).Find(&book)
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message : ": result.Error.Error(),
				"success : ": false,
			})
			return
		}
		if len(book) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"message : ": "Can't find your data !",
				"success : ": false,
			})
			return
		}
	} else if isAuthorExist {
		result = db.Where("author = ?", author).Preload("AdminLowVersion").Find(&book)
		// Preload ini ditujukan untuk foreign key agar bisa nilainya terisi
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message : ": result.Error.Error(),
				"success : ": false,
			})
			return
		}
		if len(book) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"message : ": "Can't find your data !",
				"success : ": false,
			})
			return
		}
	} else if isBookNameExist {
		result = db.Where("book_name = ?", bookName).Preload("AdminLowVersion").Find(&book)
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message : ": result.Error.Error(),
				"success : ": false,
			})
			return
		}
		if len(book) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"message : ": "Can't find your data !",
				"success : ": false,
			})
			return
		}
	}
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Success find the data of the book !",
		"success : ": true,
		"data : ":    book,
	})
	// Find akan mencari sesuai kondisi lalu kalau ketem unilainya diisikan ke variabel di dalam find tapi jika tidak akan direturn dalam bentuk error
}

func PostRequestHandler(c *gin.Context) {
	var bodyBook BookLend

	err := c.BindJSON(&bodyBook)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage : ": err.Error(),
			"success : ":  false,
		})
		return
	}
	admin := Admin{
		LibraryName: bodyBook.LibraryName,
	}
	result := db.Where("library_name = ?", bodyBook.LibraryName).Take(&admin)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	book := Book{
		BookName: bodyBook.BookName,
	}
	result = db.Where("book_name = ?", bodyBook.BookName).Take(&book)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	userCheck := User{
		Username: bodyBook.UserConfirm.UserName,
	}
	result = db.Where("username = ?", bodyBook.UserConfirm.UserName).Take(&userCheck)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	user := BookLend{
		LibraryName: bodyBook.LibraryName,
		Author:      bodyBook.Author,
		BookName:    bodyBook.BookName,
		UserConfirm: UserConfirm{
			UserName:    bodyBook.UserConfirm.UserName,
			PhoneNumber: bodyBook.UserConfirm.PhoneNumber,
			Address:     bodyBook.UserConfirm.Address,
		},
	}
	// Preload dipakai untuk isi foreign key yang diketahui attribute nya cmn satu doang, kalau banyak ga usah pakai langsung isi sendiri
	result = db.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Successfully add your request into database",
		"success : ": true,
		"data : ":    user,
	})
}

func GetConfirmFromAdminHandler(c *gin.Context) {
	userName, isUserNameExist := c.Params.Get("username")
	if !isUserNameExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage : ": "Username doesn't exist !",
			"success : ":  false,
		})
		return
	}
	var user []UserConfirmAdmin
	result := db.Where("user_name = ?", userName).Find(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var bookLend BookLendAdmin
	for _, value := range user {
		result = db.Where("user_confirm_id = ?", value.ID)
		if result.Error == nil {
			bookLend.UserConfirmAdminID = value.ID
		}
	}
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var tempUser UserConfirmAdmin
	result = db.Where("id = ?", bookLend.UserConfirmAdminID).Take(&tempUser)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	result = db.Preload("UserConfirmAdmin").Where("user_confirm_admin_id = ?", bookLend.UserConfirmAdminID).Take(&bookLend)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var admin AdminConfirm
	result = db.Preload("BookLendAdmin").Where("book_lend_admin_id = ?", bookLend.ID).Take(&admin)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(admin)
	tempAdmin := AdminConfirm{
		BookLendAdmin: BookLendAdmin{
			LibraryName: admin.BookLendAdmin.LibraryName,
			BookName:    admin.BookLendAdmin.BookName,
			Author:      admin.BookLendAdmin.Author,
			UserConfirmAdmin: UserConfirmAdmin{
				UserName:    tempUser.UserName,
				PhoneNumber: tempUser.PhoneNumber,
				Address:     tempUser.Address,
			},
		},
		Accept:     admin.Accept,
		GetBook:    admin.GetBook,
		ReturnBook: admin.ReturnBook,
		Token:      admin.Token,
	}
	fmt.Println(tempAdmin)
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Success find your request !",
		"success : ": false,
		"data : ":    tempAdmin,
	})
}

func ReturnBookHandler(c *gin.Context) {
	var bodyBook BookLend

	err := c.BindJSON(&bodyBook)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage : ": "Data doesn't valid",
			"success : ":  false,
		})
		return
	}
	var bookLend BookLendAdmin
	result := db.Preload("UserConfirmAdmin").Where("book_name = ?", bodyBook.BookName).Take(&bookLend)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(bookLend)
	var userConfirm UserConfirm
	userConfirm.Address = bookLend.UserConfirmAdmin.Address
	userConfirm.PhoneNumber = bookLend.UserConfirmAdmin.PhoneNumber
	userConfirm.UserName = bookLend.UserConfirmAdmin.UserName
	fmt.Println(userConfirm)
	var tempUserConfirm TempUserConfirm
	tempUserConfirm.Address = userConfirm.Address
	tempUserConfirm.PhoneNumber = userConfirm.PhoneNumber
	tempUserConfirm.UserName = userConfirm.UserName
	fmt.Println(tempUserConfirm)
	result = db.Create(&tempUserConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var adminConfirm AdminConfirm
	result = db.Preload("BookLendAdmin").Where("book_lend_admin_id = ?", bookLend.ID).Take(&adminConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var payment Payment
	result = db.Where("library_name = ?", bookLend.LibraryName).Take(&payment)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(payment)
	timeNow := time.Now()
	timeReturn := adminConfirm.ReturnBook
	var price float64 = 0.0
	if timeReturn.Unix()-timeNow.Unix() < 0 {
		price = (float64(timeReturn.Unix()-timeNow.Unix()) / 86400.0) * (float64(payment.Price))
	}
	fmt.Println((float64(timeReturn.Unix()-timeNow.Unix()) / 86400.0) * (float64(payment.Price)))
	var book Book
	result = db.Preload("AdminLowVersion").Where("book_name = ?", bookLend.BookName).Take(&book)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(book)
	book.Stock = book.Stock + 1
	result = db.Model(&book).Update("stock", book.Stock)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(book.Stock)
	detailLend := ReturnBookList{
		LibraryName: bodyBook.LibraryName,
		BookName:    bodyBook.BookName,
		Author:      bodyBook.Author,
		TempUserConfirm: TempUserConfirm{
			UserName:    tempUserConfirm.UserName,
			PhoneNumber: tempUserConfirm.PhoneNumber,
			Address:     tempUserConfirm.Address,
		},
		Price: uint(price),
	}
	result = db.Create(&detailLend)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(detailLend)
	c.JSON(http.StatusOK, gin.H{
		"message : ":                "Successfully return your book !",
		"successfull : ":            true,
		"data : ":                   detailLend,
		"return at :":               time.Now(),
		"return book date : ":       timeReturn,
		"payment for being late : ": uint(price),
	})
}

func GetListLendBook(c *gin.Context) {
	id, isIdExist := c.Params.Get("id")
	if !isIdExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage : ": "Can't find your username !",
			"success : ":  false,
		})
		return
	}
	var user UserConfirmAdmin
	result := db.Where("id = ?", id).Take(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var bookLendAdmin BookLendAdmin
	result = db.Preload("UserConfirmAdmin").Where("user_confirm_admin_id = ?", id).Take(&bookLendAdmin)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var adminConfirm AdminConfirm
	result = db.Preload("BookLendAdmin").Where("book_lend_admin_id = ?", bookLendAdmin.ID).Take(&adminConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	realAdminConfirm := AdminConfirm{
		Accept:     adminConfirm.Accept,
		Token:      adminConfirm.Token,
		GetBook:    adminConfirm.GetBook,
		ReturnBook: adminConfirm.ReturnBook,
		BookLendAdmin: BookLendAdmin{
			LibraryName: bookLendAdmin.LibraryName,
			BookName:    bookLendAdmin.BookName,
			Author:      bookLendAdmin.Author,
			UserConfirmAdmin: UserConfirmAdmin{
				UserName:    user.UserName,
				Address:     user.Address,
				PhoneNumber: user.PhoneNumber,
			},
		},
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Success find your data in database !",
		"success : ": true,
		"data : ":    realAdminConfirm,
	})
}

func PostExtendBookHandler(c *gin.Context) {
	id, isIdExist := c.Params.Get("id")
	if !isIdExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage : ": "Can't find your username !",
			"success : ":  false,
		})
		return
	}
	var userConfirmAdmin UserConfirmAdmin
	result := db.Where("id = ?", id).Take(&userConfirmAdmin)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var bookLend BookLendAdmin
	result = db.Where("user_confirm_admin_id = ?", id).Take(&bookLend)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var adminConfirm AdminConfirm
	result = db.Where("book_lend_admin_id = ?", bookLend.ID).Take(&adminConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	realAdminConfirm := AdminConfirm{
		Accept:     adminConfirm.Accept,
		GetBook:    adminConfirm.GetBook,
		ReturnBook: adminConfirm.ReturnBook,
		Token:      adminConfirm.Token,
		BookLendAdmin: BookLendAdmin{
			LibraryName: bookLend.LibraryName,
			Author:      bookLend.Author,
			BookName:    bookLend.BookName,
			UserConfirmAdmin: UserConfirmAdmin{
				UserName:    userConfirmAdmin.UserName,
				Address:     userConfirmAdmin.Address,
				PhoneNumber: userConfirmAdmin.PhoneNumber,
			},
		},
	}
	var tempUserConfirm []TempUserConfirm
	result = db.Where("user_name = ?", userConfirmAdmin.UserName).Find(&tempUserConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println("Panjang slice tempUser = ", len(tempUserConfirm))
	returnBookList := make([]ReturnBookList, len(tempUserConfirm))
	fmt.Println("Panjang slice returnbooklist = ", len(returnBookList))
	for i, value := range returnBookList {
		result = db.Where("temp_user_confirm_id = ?", tempUserConfirm[i].ID).Take(&value)
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message : ": result.Error.Error(),
				"success : ": false,
			})
			return
		}
		if value.Price > 0 {
			c.JSON(http.StatusForbidden, gin.H{
				"message : ": "You still have some money fine to paid. Please pay it first so you can lend our book again !",
				"success : ": false,
			})
			return
		}
	}
	fmt.Println(adminConfirm.ReturnBook)
	adminConfirm.ReturnBook = adminConfirm.ReturnBook.Local().AddDate(0, 0, 7)
	fmt.Println(adminConfirm.ReturnBook)
	result = db.Model(&adminConfirm).Update("return_book", adminConfirm.ReturnBook)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ":     "Successfully extend your return book deadline !",
		"success : ":     true,
		"data : ":        realAdminConfirm,
		"extended to : ": adminConfirm.ReturnBook,
	})
}

func PostSignupHandlerAdmin(c *gin.Context) {
	var bodyUser Admin
	err := c.BindJSON(&bodyUser)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": err.Error(),
			"success : ": false,
		})
		return
	}
	if len(bodyUser.Password) < 8 || len(bodyUser.Password) > 16 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "Password length must be between 8-16 !",
			"success : ": false,
		})
		return
	}
	if strings.Contains(bodyUser.Password, "!") || strings.Contains(bodyUser.Password, "@") || strings.Contains(bodyUser.Password, "#") || strings.Contains(bodyUser.Password, "$") || strings.Contains(bodyUser.Password, "%") || strings.Contains(bodyUser.Password, "^") || strings.Contains(bodyUser.Password, "&") || strings.Contains(bodyUser.Password, "*") || strings.Contains(bodyUser.Password, "(") || strings.Contains(bodyUser.Password, "\"") || strings.Contains(bodyUser.Password, "~") || strings.Contains(bodyUser.Password, "+") || strings.Contains(bodyUser.Password, "=") || strings.Contains(bodyUser.Password, "{") || strings.Contains(bodyUser.Password, "}") || strings.Contains(bodyUser.Password, "|") || strings.Contains(bodyUser.Password, ":") || strings.Contains(bodyUser.Password, ";") || strings.Contains(bodyUser.Password, "<") || strings.Contains(bodyUser.Password, ">") || strings.Contains(bodyUser.Password, ",") || strings.Contains(bodyUser.Password, ".") || strings.Contains(bodyUser.Password, "?") || strings.Contains(bodyUser.Password, "/") {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "Password only can contain some symbols(-,_), numbers, or letters !",
			"success : ": false,
		})
		return
	}
	user := Admin{
		Email:         bodyUser.Email,
		Password:      bodyUser.Password,
		LibraryName:   bodyUser.LibraryName,
		Province:      bodyUser.Province,
		City:          bodyUser.City,
		District:      bodyUser.District,
		Neighborhoods: bodyUser.Neighborhoods,
		Address:       bodyUser.Address,
		PhoneNumber:   bodyUser.PhoneNumber,
		TimeOpenClose: bodyUser.TimeOpenClose,
	}
	result := db.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Registration Success",
		"success : ": true,
		"data : ": gin.H{
			"libraryname : ":   bodyUser.LibraryName,
			"province : ":      bodyUser.Province,
			"city : ":          bodyUser.City,
			"district : ":      bodyUser.District,
			"neighborhoods : ": bodyUser.Neighborhoods,
			"address : ":       bodyUser.Address,
			"open - close":     bodyUser.TimeOpenClose,
		},
	})
}

func PostLoginHandlerAdmin(c *gin.Context) {
	var bodyLogin Login
	err := c.BindJSON(&bodyLogin)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": err.Error(),
			"success : ": false,
		})
		return
	}

	var user Admin
	result := db.Where("email = ?", bodyLogin.Email).Find(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	if user.Password == bodyLogin.Password {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":  user.ID,
			"exp": time.Now().Add(time.Hour * 24 * 14).Unix(),
		})
		tokenString, err := token.SignedString([]byte("passwordBuatSigningAdmin"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "Error when generating the token.",
				"error":   err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message : ": "Success Login !",
			"Token : ":   tokenString,
			"success : ": true,
		})
		return
	} else {
		c.JSON(http.StatusForbidden, gin.H{
			"message : ": "Wrong email or password !",
			"success : ": false,
		})
		return
	}
}

func PostAddBookHandler(c *gin.Context) {
	var bodyBook Book
	err := c.BindJSON(&bodyBook)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": err.Error(),
			"success : ": false,
		})
		return
	}
	var admin Admin
	result := db.Where("library_name = ?", bodyBook.AdminLowVersion.LibraryName).Take(&admin)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	tempBook := Book{
		ID:       bodyBook.ID,
		BookName: bodyBook.BookName,
		Author:   bodyBook.Author,
		Synopsis: bodyBook.Synopsis,
		Stock:    bodyBook.Stock,
		ISBN:     bodyBook.ISBN,
		AdminLowVersion: AdminLowVersion{
			LibraryName: bodyBook.AdminLowVersion.LibraryName,
			Address:     bodyBook.AdminLowVersion.Address,
			City:        bodyBook.AdminLowVersion.City,
			PhoneNumber: bodyBook.AdminLowVersion.PhoneNumber,
			Province:    bodyBook.AdminLowVersion.Province,
		},
	}
	result = db.Create(&tempBook)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Successfully add your book into database!",
		"success : ": true,
		"data : ":    tempBook,
	})
}

func PatchEditBookHandler(c *gin.Context) {
	id, idExist := c.Params.Get("id")
	// id buku
	if !idExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "ID doesn't exist",
			"success : ": false,
		})
		return
	}
	var book Book
	res := db.Where("id = ?", id).Take(&book)
	if res.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": res.Error.Error(),
			"success : ": false,
		})
		return
	}
	var admin AdminLowVersion
	res = db.Where("id = ?", book.AdminLowVersionID).Take(&admin)
	if res.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": res.Error.Error(),
			"success : ": false,
		})
		return
	}
	var bodyBook Book
	err := c.BindJSON(&bodyBook)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": err.Error(),
			"success : ": false,
		})
		return
	}
	convertID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": err.Error(),
			"success : ": false,
		})
		return
	}
	tempBook := Book{
		ID:       uint(convertID),
		BookName: bodyBook.BookName,
		Author:   bodyBook.Author,
		Synopsis: bodyBook.Synopsis,
		Stock:    bodyBook.Stock,
		ISBN:     bodyBook.ISBN,
		AdminLowVersion: AdminLowVersion{
			LibraryName: admin.LibraryName,
			Address:     admin.Address,
			City:        admin.City,
			PhoneNumber: admin.PhoneNumber,
			Province:    admin.Province,
		},
	}
	result := db.Model(&tempBook).Where("id = ?", convertID).Updates(&tempBook)
	// Model yang mau diupdate objeknya siapa, updates itu lebih ke nanti isi yg diupdate itu
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	result = db.Where("id = ?", id).Take(&tempBook)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success ":   false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Successfully update the book!",
		"success ":   true,
		"data":       tempBook,
	})
}

func DeleteBookHandler(c *gin.Context) {
	id, isIdExist := c.Params.Get("id")
	if !isIdExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "Can't found your book!",
			"success : ": false,
		})
		return
	}
	var book Book
	result := db.Where("id = ?", id)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": "Error when deleting your data in database !",
			"success : ": false,
		})
		return
	}
	result = db.Delete(&book)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": "Error when deleting your data in database !",
			"success : ": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Successfully delete your book!",
		"success : ": false,
	})
}

func GetProfileHandler(c *gin.Context) {
	id, isIdExist := c.Params.Get("id")
	if !isIdExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "Can't find your library profile !",
			"success : ": false,
		})
		return
	}
	convertID, _ := strconv.ParseUint(id, 10, 64)
	libraryProfile := Admin{
		ID: uint(convertID),
	}
	result := db.Where("id= ?", convertID).Find(&libraryProfile)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	if libraryProfile.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "Can't find your data !",
			"success : ": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Success find your profile in database !",
		"success : ": true,
		"data : ": gin.H{
			"libraryname : ":   libraryProfile.LibraryName,
			"province : ":      libraryProfile.Province,
			"city : ":          libraryProfile.City,
			"district : ":      libraryProfile.District,
			"neighborhoods : ": libraryProfile.Neighborhoods,
			"address : ":       libraryProfile.Address,
		},
	})
}

func GetRequestHandler(c *gin.Context) {
	libraryName, isLibraryNameExist := c.Params.Get("libraryname")
	if !isLibraryNameExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "Library name doesn't exist !",
			"success : ": false,
		})
		return
	}
	var user []BookLend
	result := db.Where("library_name = ?", libraryName).Preload("UserConfirm").Find(&user)
	// Find bakal isi nilai kalau sesuai syarat
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	if len(user) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "No data found !",
			"success : ": false,
		})
		return
	}
	tempUser := make([]BookLend, len(user))
	for i, value := range user {
		tempUser[i] = BookLend{
			ID:          value.ID,
			LibraryName: value.LibraryName,
			BookName:    value.BookName,
			Author:      value.Author,
			UserConfirm: UserConfirm{
				ID:          value.UserConfirm.ID,
				PhoneNumber: value.UserConfirm.PhoneNumber,
				UserName:    value.UserConfirm.UserName,
				Address:     value.UserConfirm.Address,
			},
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Successfully find all request from user !",
		"success : ": true,
		"data : ":    tempUser,
	})
}

func PostConfirmHandler(c *gin.Context) {
	var bodyConfirm AdminConfirm

	err := c.BindJSON(&bodyConfirm)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": "Can't found response from admin !",
			"success : ": false,
		})
		return
	}
	var userRequest BookLend
	result := db.Preload("UserConfirm").Where("library_name = ?", bodyConfirm.BookLendAdmin.LibraryName).Where("book_name = ?", bodyConfirm.BookLendAdmin.BookName).Where("author = ?", bodyConfirm.BookLendAdmin.Author).Take(&userRequest)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(bodyConfirm)
	// Buat cek apakah beneran ada datanya di Tabel BookLend
	// userConfirmAdmin := UserConfirmAdmin{
	// 	UserName: ,

	// }

	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, 10)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	adminConfirm := AdminConfirm{
		Accept: bodyConfirm.Accept,
		BookLendAdmin: BookLendAdmin{
			BookName:    bodyConfirm.BookLendAdmin.BookName,
			Author:      bodyConfirm.BookLendAdmin.Author,
			LibraryName: bodyConfirm.BookLendAdmin.LibraryName,
			UserConfirmAdmin: UserConfirmAdmin{
				UserName:    bodyConfirm.BookLendAdmin.UserConfirmAdmin.UserName,
				Address:     bodyConfirm.BookLendAdmin.UserConfirmAdmin.Address,
				PhoneNumber: bodyConfirm.BookLendAdmin.UserConfirmAdmin.PhoneNumber,
			},
		},
		ReturnBook: time.Now(),
		GetBook:    time.Now(),
		Token:      "-",
	}
	fmt.Println(bodyConfirm)
	fmt.Println(adminConfirm)
	var book Book
	result = db.Where("book_name = ?", bodyConfirm.BookLendAdmin.BookName).Take(&book)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println("Isi Book adalah ", book.Stock)
	if bodyConfirm.Accept == "Diterima" || bodyConfirm.Accept == "diterima" || bodyConfirm.Accept == "Y" || bodyConfirm.Accept == "y" {
		book.Stock = book.Stock - 1
		result = db.Model(&book).Where("book_name = ?", bodyConfirm.BookLendAdmin.BookName).Update("stock", book.Stock)
		fmt.Println("Setelah diacc, stock tersisa adalah", book.Stock)
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message : ": result.Error.Error(),
				"success : ": false,
			})
			return
		}
		adminConfirm.ReturnBook = time.Now().Local().AddDate(0, 0, 7)
		adminConfirm.GetBook = time.Now().Local()
		adminConfirm.Token = string(s)
	}
	fmt.Println("admin confirm yang sekarang", adminConfirm)
	result = db.Create(&adminConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Success sending confirmation to the user !",
		"success : ": true,
		"data : ":    adminConfirm,
	})
}

func PostPaymentHandler(c *gin.Context) {
	var payment Payment

	err := c.BindJSON(&payment)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message : ": err.Error(),
			"success : ": false,
		})
		return
	}
	result := db.Where("library_name = ?", payment.LibraryName)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	result = db.Create(&payment)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message : ": "Successfully add your payment data into database !",
		"success : ": false,
		"data : ":    payment,
	})
}
