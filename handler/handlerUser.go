package handler

import (
	"LibNow/config"
	"LibNow/model"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func PostSignupHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var bodyUser model.User

	err = c.BindJSON(&bodyUser)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	if strings.Contains(bodyUser.EmailOrPhoneNumber, "!") || strings.Contains(bodyUser.EmailOrPhoneNumber, "#") || strings.Contains(bodyUser.EmailOrPhoneNumber, "$") || strings.Contains(bodyUser.EmailOrPhoneNumber, "%") || strings.Contains(bodyUser.EmailOrPhoneNumber, "^") || strings.Contains(bodyUser.EmailOrPhoneNumber, "&") || strings.Contains(bodyUser.EmailOrPhoneNumber, "*") || strings.Contains(bodyUser.EmailOrPhoneNumber, "(") || strings.Contains(bodyUser.EmailOrPhoneNumber, "\"") || strings.Contains(bodyUser.EmailOrPhoneNumber, "~") || strings.Contains(bodyUser.EmailOrPhoneNumber, "+") || strings.Contains(bodyUser.EmailOrPhoneNumber, "=") || strings.Contains(bodyUser.EmailOrPhoneNumber, "{") || strings.Contains(bodyUser.EmailOrPhoneNumber, "}") || strings.Contains(bodyUser.EmailOrPhoneNumber, "|") || strings.Contains(bodyUser.EmailOrPhoneNumber, ":") || strings.Contains(bodyUser.EmailOrPhoneNumber, ";") || strings.Contains(bodyUser.EmailOrPhoneNumber, "<") || strings.Contains(bodyUser.EmailOrPhoneNumber, ">") || strings.Contains(bodyUser.EmailOrPhoneNumber, ",") || strings.Contains(bodyUser.EmailOrPhoneNumber, "?") || strings.Contains(bodyUser.EmailOrPhoneNumber, "/") {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email only can contain some symbols(_,@), numbers, or letters !",
			"success": false,
		})
		return
	}
	if len(bodyUser.Password) < 8 || len(bodyUser.Password) > 16 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Password length must be between 8-16 !",
			"success": false,
		})
		return
	}
	if strings.Contains(bodyUser.Password, "!") || strings.Contains(bodyUser.Password, "@") || strings.Contains(bodyUser.Password, "#") || strings.Contains(bodyUser.Password, "$") || strings.Contains(bodyUser.Password, "%") || strings.Contains(bodyUser.Password, "^") || strings.Contains(bodyUser.Password, "&") || strings.Contains(bodyUser.Password, "*") || strings.Contains(bodyUser.Password, "(") || strings.Contains(bodyUser.Password, "\"") || strings.Contains(bodyUser.Password, "~") || strings.Contains(bodyUser.Password, "+") || strings.Contains(bodyUser.Password, "=") || strings.Contains(bodyUser.Password, "{") || strings.Contains(bodyUser.Password, "}") || strings.Contains(bodyUser.Password, "|") || strings.Contains(bodyUser.Password, ":") || strings.Contains(bodyUser.Password, ";") || strings.Contains(bodyUser.Password, "<") || strings.Contains(bodyUser.Password, ">") || strings.Contains(bodyUser.Password, ",") || strings.Contains(bodyUser.Password, ".") || strings.Contains(bodyUser.Password, "?") || strings.Contains(bodyUser.Password, "/") {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Password only can contain some symbols(-,_), numbers, or letters !",
			"success": false,
		})
		return
	}
	user := model.User{
		ID:                 bodyUser.ID,
		EmailOrPhoneNumber: bodyUser.EmailOrPhoneNumber,
		Password:           bodyUser.Password,
		Username:           bodyUser.Username,
	}
	result := db.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Registration succesfully !",
		"success": true,
		"data": gin.H{
			"username":           user.Username,
			"email/phone number": user.EmailOrPhoneNumber,
		},
	})
}

func PostLoginHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var bodyLogin model.User

	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "POST")

	err = c.BindJSON(&bodyLogin)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var user model.User
	result := db.Where("email_or_phone_number = ?", bodyLogin.EmailOrPhoneNumber).Take(&user)
	// ? nanti akan diisi sama bodyLogin.EmailOrPhoneNumber
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
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
			"message": "Success Login !",
			"id":      user.ID,
			"Token":   tokenString,
			"success": true,
		})
		return
	} else {
		c.JSON(http.StatusForbidden, gin.H{
			"message": "Wrong email or password !",
			"success": false,
		})
		return
	}
}

func GetLibraryInfoHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var getAdmin []model.Admin

	result := db.Find(&getAdmin)
	// Find akan mencari data dari type data yang ada pada variabel tersebut

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}

	var tempAdmin []gin.H
	for _, value := range getAdmin {
		tempAdmin = append(tempAdmin, gin.H{
			"libraryname":  value.LibraryName,
			"province":     value.Province,
			"city":         value.City,
			"district":     value.District,
			"neigborhoods": value.Neighborhoods,
			"phonenumber":  value.PhoneNumber,
			"open - close": value.TimeOpenClose,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully get the data !",
		"data":    tempAdmin,
	})
}

func GetBookInfoHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	author, isAuthorExist := c.GetQuery("author")
	bookName, isBookNameExist := c.GetQuery("bookname")

	if !isAuthorExist && !isBookNameExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage": "Can't find author or bookname !",
			"success":  false,
		})
		return
	}
	// pakai c.Query kalau tidak wajib 2 2 , pakai getQuery kalau wajib 2 2
	var book []model.Book
	book = append(book, model.Book{
		Author:   author,
		BookName: bookName,
	})
	result := db
	if isAuthorExist && isBookNameExist {
		result := db.Where("author = ?", author).Where("book_name = ?", bookName).Find(&book)
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": result.Error.Error(),
				"success": false,
			})
			return
		}
		if len(book) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Can't find your data !",
				"success": false,
			})
			return
		}
	} else if isAuthorExist {
		result = db.Where("author = ?", author).Preload("AdminLowVersion").Find(&book)
		// Preload ini ditujukan untuk foreign key agar bisa nilainya terisi
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": result.Error.Error(),
				"success": false,
			})
			return
		}
		if len(book) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Can't find your data !",
				"success": false,
			})
			return
		}
	} else if isBookNameExist {
		result = db.Where("book_name = ?", bookName).Preload("AdminLowVersion").Find(&book)
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": result.Error.Error(),
				"success": false,
			})
			return
		}
		if len(book) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Can't find your data !",
				"success": false,
			})
			return
		}
	}
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Success find the data of the book !",
		"success": true,
		"data":    book,
	})
	// Find akan mencari sesuai kondisi lalu kalau ketem unilainya diisikan ke variabel di dalam find tapi jika tidak akan direturn dalam bentuk error
}

func PostRequestHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var bodyBook model.BookLend

	err = c.BindJSON(&bodyBook)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage": err.Error(),
			"success":  false,
		})
		return
	}
	admin := model.Admin{
		LibraryName: bodyBook.LibraryName,
	}
	result := db.Where("library_name = ?", bodyBook.LibraryName).Take(&admin)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	book := model.Book{
		BookName: bodyBook.BookName,
	}
	result = db.Where("book_name = ?", bodyBook.BookName).Take(&book)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	userCheck := model.User{
		Username: bodyBook.UserConfirm.UserName,
	}
	result = db.Where("username = ?", bodyBook.UserConfirm.UserName).Take(&userCheck)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	user := model.BookLend{
		LibraryName: bodyBook.LibraryName,
		Author:      bodyBook.Author,
		BookName:    bodyBook.BookName,
		UserConfirm: model.UserConfirm{
			UserName:    bodyBook.UserConfirm.UserName,
			PhoneNumber: bodyBook.UserConfirm.PhoneNumber,
			Address:     bodyBook.UserConfirm.Address,
		},
	}
	// Preload dipakai untuk isi foreign key yang diketahui attribute nya cmn satu doang, kalau banyak ga usah pakai langsung isi sendiri
	result = db.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully add your request into database",
		"success": true,
		"data":    user,
	})
}

func GetConfirmFromAdminHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	id, isUserNameExist := c.Params.Get("id")
	if !isUserNameExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage": "Username doesn't exist !",
			"success":  false,
		})
		return
	}
	var user []model.UserConfirmAdmin
	result := db.Where("id = ?", id).Find(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	var bookLend model.BookLendAdmin
	for _, value := range user {
		result = db.Where("user_confirm_id = ?", value.ID)
		if result.Error == nil {
			bookLend.UserConfirmAdminID = value.ID
		}
	}
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	var tempUser model.UserConfirmAdmin
	result = db.Where("id = ?", bookLend.UserConfirmAdminID).Take(&tempUser)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	result = db.Preload("UserConfirmAdmin").Where("user_confirm_admin_id = ?", bookLend.UserConfirmAdminID).Take(&bookLend)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	var admin model.AdminConfirm
	result = db.Preload("BookLendAdmin").Where("book_lend_admin_id = ?", bookLend.ID).Take(&admin)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	fmt.Println(admin)
	tempAdmin := model.AdminConfirm{
		BookLendAdmin: model.BookLendAdmin{
			LibraryName: admin.BookLendAdmin.LibraryName,
			BookName:    admin.BookLendAdmin.BookName,
			Author:      admin.BookLendAdmin.Author,
			UserConfirmAdmin: model.UserConfirmAdmin{
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
		"message": "Success find your request !",
		"success": false,
		"data":    tempAdmin,
	})
}

func ReturnBookHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var bodyBook model.BookLend

	err = c.BindJSON(&bodyBook)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage": "Data doesn't valid",
			"success":  false,
		})
		return
	}
	var bookLend model.BookLendAdmin
	result := db.Preload("UserConfirmAdmin").Where("book_name = ?", bodyBook.BookName).Take(&bookLend)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	fmt.Println(bookLend)
	var userConfirm model.UserConfirm
	userConfirm.Address = bookLend.UserConfirmAdmin.Address
	userConfirm.PhoneNumber = bookLend.UserConfirmAdmin.PhoneNumber
	userConfirm.UserName = bookLend.UserConfirmAdmin.UserName
	fmt.Println(userConfirm)
	var tempUserConfirm model.TempUserConfirm
	tempUserConfirm.Address = userConfirm.Address
	tempUserConfirm.PhoneNumber = userConfirm.PhoneNumber
	tempUserConfirm.UserName = userConfirm.UserName
	fmt.Println(tempUserConfirm)
	result = db.Create(&tempUserConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	var adminConfirm model.AdminConfirm
	result = db.Preload("BookLendAdmin").Where("book_lend_admin_id = ?", bookLend.ID).Take(&adminConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	var payment model.Payment
	result = db.Where("library_name = ?", bookLend.LibraryName).Take(&payment)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
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
	var book model.Book
	result = db.Preload("AdminLowVersion").Where("book_name = ?", bookLend.BookName).Take(&book)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	fmt.Println(book)
	book.Stock = book.Stock + 1
	result = db.Model(&book).Update("stock", book.Stock)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	fmt.Println(book.Stock)
	detailLend := model.ReturnBookList{
		LibraryName: bodyBook.LibraryName,
		BookName:    bodyBook.BookName,
		Author:      bodyBook.Author,
		TempUserConfirm: model.TempUserConfirm{
			UserName:    tempUserConfirm.UserName,
			PhoneNumber: tempUserConfirm.PhoneNumber,
			Address:     tempUserConfirm.Address,
		},
		Price: uint(price),
	}
	result = db.Create(&detailLend)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	fmt.Println(detailLend)
	c.JSON(http.StatusOK, gin.H{
		"message":                "Successfully return your book !",
		"successfull":            true,
		"data":                   detailLend,
		"return at :":            time.Now(),
		"return book date":       timeReturn,
		"payment for being late": uint(price),
	})
}

func GetListLendBook(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	id, isIdExist := c.Params.Get("id")
	if !isIdExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage": "Can't find your username !",
			"success":  false,
		})
		return
	}
	var user model.UserConfirmAdmin
	result := db.Where("id = ?", id).Take(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	var bookLendAdmin model.BookLendAdmin
	result = db.Preload("UserConfirmAdmin").Where("user_confirm_admin_id = ?", id).Take(&bookLendAdmin)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	var adminConfirm model.AdminConfirm
	result = db.Preload("BookLendAdmin").Where("book_lend_admin_id = ?", bookLendAdmin.ID).Take(&adminConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	realAdminConfirm := model.AdminConfirm{
		Accept:     adminConfirm.Accept,
		Token:      adminConfirm.Token,
		GetBook:    adminConfirm.GetBook,
		ReturnBook: adminConfirm.ReturnBook,
		BookLendAdmin: model.BookLendAdmin{
			LibraryName: bookLendAdmin.LibraryName,
			BookName:    bookLendAdmin.BookName,
			Author:      bookLendAdmin.Author,
			UserConfirmAdmin: model.UserConfirmAdmin{
				UserName:    user.UserName,
				Address:     user.Address,
				PhoneNumber: user.PhoneNumber,
			},
		},
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Success find your data in database !",
		"success": true,
		"data":    realAdminConfirm,
	})
}

func PostExtendBookHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	id, isIdExist := c.Params.Get("id")
	if !isIdExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"messsage": "Can't find your username !",
			"success":  false,
		})
		return
	}
	var userConfirmAdmin model.UserConfirmAdmin
	result := db.Where("id = ?", id).Take(&userConfirmAdmin)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	var bookLend model.BookLendAdmin
	result = db.Where("user_confirm_admin_id = ?", id).Take(&bookLend)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	var adminConfirm model.AdminConfirm
	result = db.Where("book_lend_admin_id = ?", bookLend.ID).Take(&adminConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	realAdminConfirm := model.AdminConfirm{
		Accept:     adminConfirm.Accept,
		GetBook:    adminConfirm.GetBook,
		ReturnBook: adminConfirm.ReturnBook,
		Token:      adminConfirm.Token,
		BookLendAdmin: model.BookLendAdmin{
			LibraryName: bookLend.LibraryName,
			Author:      bookLend.Author,
			BookName:    bookLend.BookName,
			UserConfirmAdmin: model.UserConfirmAdmin{
				UserName:    userConfirmAdmin.UserName,
				Address:     userConfirmAdmin.Address,
				PhoneNumber: userConfirmAdmin.PhoneNumber,
			},
		},
	}
	var tempUserConfirm []model.TempUserConfirm
	result = db.Where("user_name = ?", userConfirmAdmin.UserName).Find(&tempUserConfirm)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	fmt.Println("Panjang slice tempUser = ", len(tempUserConfirm))
	returnBookList := make([]model.ReturnBookList, len(tempUserConfirm))
	fmt.Println("Panjang slice returnbooklist = ", len(returnBookList))
	for i, value := range returnBookList {
		result = db.Where("temp_user_confirm_id = ?", tempUserConfirm[i].ID).Take(&value)
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": result.Error.Error(),
				"success": false,
			})
			return
		}
		if value.Price > 0 {
			c.JSON(http.StatusForbidden, gin.H{
				"message": "You still have some money fine to paid. Please pay it first so you can lend our book again !",
				"success": false,
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
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":     "Successfully extend your return book deadline !",
		"success":     true,
		"data":        realAdminConfirm,
		"extended to": adminConfirm.ReturnBook,
	})
}

func GetProfileUserHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	id, isIDExist := c.Params.Get("id")
	if !isIDExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Your profile doesn't exist !",
			"success": false,
		})
		return
	}
	var user model.User
	result := db.Where("id = ?", id).Take(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Success find your data !",
		"success": true,
		"data": gin.H{
			"username":          user.Username,
			"email/phonenumber": user.EmailOrPhoneNumber,
		},
	})
}
