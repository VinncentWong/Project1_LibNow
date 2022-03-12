package handler

import (
	"LibNow/config"
	"LibNow/model"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func PostSignupHandlerAdmin(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var bodyUser model.Admin
	err = c.BindJSON(&bodyUser)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
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
	user := model.Admin{
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
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Registration Success",
		"success": true,
		"data": gin.H{
			"libraryname":   bodyUser.LibraryName,
			"province":      bodyUser.Province,
			"city":          bodyUser.City,
			"district":      bodyUser.District,
			"neighborhoods": bodyUser.Neighborhoods,
			"address":       bodyUser.Address,
			"open - close":  bodyUser.TimeOpenClose,
		},
	})
}

func PostLoginHandlerAdmin(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var bodyLogin model.Login
	err = c.BindJSON(&bodyLogin)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}

	var user model.Admin
	result := db.Where("email = ?", bodyLogin.Email).Take(&user)
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

func PostAddBookHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var bodyBook model.Book
	err = c.BindJSON(&bodyBook)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var admin model.Admin
	result := db.Where("library_name = ?", bodyBook.AdminLowVersion.LibraryName).Take(&admin)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	tempBook := model.Book{
		ID:       bodyBook.ID,
		BookName: bodyBook.BookName,
		Author:   bodyBook.Author,
		Synopsis: bodyBook.Synopsis,
		Stock:    bodyBook.Stock,
		ISBN:     bodyBook.ISBN,
		AdminLowVersion: model.AdminLowVersion{
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
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully add your book into database!",
		"success": true,
		"data":    tempBook,
	})
}

func PatchEditBookHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	id, idExist := c.Params.Get("id")
	// id buku
	if !idExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "ID doesn't exist",
			"success": false,
		})
		return
	}
	var book model.Book
	res := db.Where("id = ?", id).Take(&book)
	if res.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": res.Error.Error(),
			"success": false,
		})
		return
	}
	var admin model.AdminLowVersion
	res = db.Where("id = ?", book.AdminLowVersionID).Take(&admin)
	if res.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": res.Error.Error(),
			"success": false,
		})
		return
	}
	var bodyBook model.Book
	err = c.BindJSON(&bodyBook)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	convertID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	tempBook := model.Book{
		ID:       uint(convertID),
		BookName: bodyBook.BookName,
		Author:   bodyBook.Author,
		Synopsis: bodyBook.Synopsis,
		Stock:    bodyBook.Stock,
		ISBN:     bodyBook.ISBN,
		AdminLowVersion: model.AdminLowVersion{
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
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	result = db.Where("id = ?", id).Take(&tempBook)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message":  result.Error.Error(),
			"success ": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":  "Successfully update the book!",
		"success ": true,
		"data":     tempBook,
	})
}

func DeleteBookHandler(c *gin.Context) {
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
			"message": "Can't found your book!",
			"success": false,
		})
		return
	}
	var book model.Book
	result := db.Where("id = ?", id)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error when deleting your data in database !",
			"success": false,
		})
		return
	}
	result = db.Delete(&book)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error when deleting your data in database !",
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully delete your book!",
		"success": false,
	})
}

func GetProfileHandler(c *gin.Context) {
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
			"message": "Can't find your library profile !",
			"success": false,
		})
		return
	}
	convertID, _ := strconv.ParseUint(id, 10, 64)
	libraryProfile := model.Admin{
		ID: uint(convertID),
	}
	result := db.Where("id= ?", convertID).Find(&libraryProfile)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	if libraryProfile.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Can't find your data !",
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Success find your profile in database !",
		"success": true,
		"data": gin.H{
			"libraryname":   libraryProfile.LibraryName,
			"province":      libraryProfile.Province,
			"city":          libraryProfile.City,
			"district":      libraryProfile.District,
			"neighborhoods": libraryProfile.Neighborhoods,
			"address":       libraryProfile.Address,
		},
	})
}

func GetRequestHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	id, isLibraryNameExist := c.Params.Get("id")
	if !isLibraryNameExist {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Library name doesn't exist !",
			"success": false,
		})
		return
	}
	var user []model.BookLend
	result := db.Where("id = ?", id).Preload("UserConfirm").Find(&user)
	// Find bakal isi nilai kalau sesuai syarat
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	if len(user) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "No data found !",
			"success": false,
		})
		return
	}
	tempUser := make([]model.BookLend, len(user))
	for i, value := range user {
		tempUser[i] = model.BookLend{
			ID:          value.ID,
			LibraryName: value.LibraryName,
			BookName:    value.BookName,
			Author:      value.Author,
			UserConfirm: model.UserConfirm{
				ID:          value.UserConfirm.ID,
				PhoneNumber: value.UserConfirm.PhoneNumber,
				UserName:    value.UserConfirm.UserName,
				Address:     value.UserConfirm.Address,
			},
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully find all request from user !",
		"success": true,
		"data":    tempUser,
	})
}

func PostConfirmHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var bodyConfirm model.AdminConfirm

	err = c.BindJSON(&bodyConfirm)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Can't found response from admin !",
			"success": false,
		})
		return
	}
	var userRequest model.BookLend
	result := db.Preload("UserConfirm").Where("library_name = ?", bodyConfirm.BookLendAdmin.LibraryName).Where("book_name = ?", bodyConfirm.BookLendAdmin.BookName).Where("author = ?", bodyConfirm.BookLendAdmin.Author).Take(&userRequest)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
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
	adminConfirm := model.AdminConfirm{
		Accept: bodyConfirm.Accept,
		BookLendAdmin: model.BookLendAdmin{
			BookName:    bodyConfirm.BookLendAdmin.BookName,
			Author:      bodyConfirm.BookLendAdmin.Author,
			LibraryName: bodyConfirm.BookLendAdmin.LibraryName,
			UserConfirmAdmin: model.UserConfirmAdmin{
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
	var book model.Book
	result = db.Where("book_name = ?", bodyConfirm.BookLendAdmin.BookName).Take(&book)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
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
				"message": result.Error.Error(),
				"success": false,
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
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Success sending confirmation to the user !",
		"success": true,
		"data":    adminConfirm,
	})
}

func PostPaymentHandler(c *gin.Context) {
	db, err := config.InitDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	var payment model.Payment

	err = c.BindJSON(&payment)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	result := db.Where("library_name = ?", payment.LibraryName)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	result = db.Create(&payment)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": result.Error.Error(),
			"success": false,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully add your payment data into database !",
		"success": false,
		"data":    payment,
	})
}
