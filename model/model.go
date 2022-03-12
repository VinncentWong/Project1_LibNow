package model

import (
	"time"
)

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
