package main

import (
	"fmt"
	"net/http"
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
	router.Use(cors.Default())
	InitRouter()
	router.Run()
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
	err = db.AutoMigrate(&User{}, &UserConfirm{}, &BookLend{}, &Payment{})
	if err != nil {
		return err
	}
	return nil
}

func InitRouter() {
	router.POST("/user/signup", PostSignupHandler)
	router.POST("/user/login", PostLoginHandler)
	router.GET("/user/libraryinfo", GetLibraryInfoHandler)
	router.GET("/user/getbookinfo", GetBookInfoHandler)
	router.POST("/user/request", AuthMiddleware(), PostRequestHandler)
	router.GET("/user/requestinfo/:username", AuthMiddleware(), GetConfirmFromAdminHandler)
	router.POST("/user/returnbook", AuthMiddleware(), ReturnBookHandler)
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
	AdminLowVersion   AdminLowVersion
	AdminLowVersionID uint
}

type AdminConfirm struct {
	ID         uint `gorm:"primarykey"`
	BookLend   BookLend
	BookLendID uint
	Accept     string `json:"confirm"`
	GetBook    time.Time
	ReturnBook time.Time
	Token      string
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
	var user []UserConfirm
	result := db.Where("user_name = ?", userName).Find(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var bookLend BookLend
	for _, value := range user {
		result = db.Where("user_confirm_id = ?", value.ID)
		if result.Error == nil {
			bookLend.UserConfirmID = value.ID
		}
	}
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var tempUser UserConfirm
	result = db.Where("id = ?", bookLend.UserConfirmID).Take(&tempUser)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	result = db.Preload("UserConfirm").Where("user_confirm_id = ?", bookLend.UserConfirmID).Take(&bookLend)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	var admin AdminConfirm
	result = db.Preload("BookLend").Where("book_lend_id = ?", bookLend.ID).Take(&admin)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(admin)
	tempAdmin := AdminConfirm{
		BookLend: BookLend{
			LibraryName: admin.BookLend.LibraryName,
			BookName:    admin.BookLend.BookName,
			Author:      admin.BookLend.Author,
			UserConfirm: UserConfirm{
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
			"messsage : ": err.Error(),
			"success : ":  false,
		})
		return
	}
	var user UserConfirm
	result := db.Where("user_name = ?", bodyBook.UserConfirm.UserName).Take(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(user)
	var bookLend BookLend
	result = db.Preload("UserConfirm").Where("user_confirm_id = ?", user.ID).Take(&bookLend)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(bookLend)
	var adminConfirm AdminConfirm
	result = db.Preload("BookLend").Where("book_lend_id = ?", bookLend.ID).Take(&adminConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(adminConfirm)
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
		c.JSON(http.StatusOK, gin.H{
			"message : ": result.Error.Error(),
			"success : ": false,
		})
		return
	}
	fmt.Println(book)
	book.Stock = book.Stock + 1
	fmt.Println(book.Stock)
	c.JSON(http.StatusOK, gin.H{
		"message : ":                "Successfully return your book !",
		"successfull : ":            true,
		"data : ":                   bodyBook,
		"return at :":               time.Now(),
		"return book date : ":       timeReturn,
		"payment for being late : ": uint(price),
	})
}
