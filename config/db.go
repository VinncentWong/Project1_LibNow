package config

import (
	"LibNow/model"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func InitDB() error {
	db, err := gorm.Open(mysql.Open("root:@tcp(127.0.0.1:3306)/project1_libnow?parseTime=true"), &gorm.Config{})
	if err != nil {
		return err
	}
	err = db.AutoMigrate(&model.User{}, &model.UserConfirm{}, &model.BookLend{}, &model.Payment{}, &model.ReturnBookList{}, &model.TempUserConfirm{}, &model.Admin{}, &model.Book{}, &model.AdminLowVersion{}, &model.AdminConfirm{}, &model.BookLendAdmin{}, &model.UserConfirmAdmin{})
	if err != nil {
		return err
	}
	return nil
}
