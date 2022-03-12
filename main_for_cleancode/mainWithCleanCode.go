package main

import (
	"LibNow/AuthMiddleware"
	"LibNow/handler"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	router.POST("/user/signup", handler.PostSignupHandler)
	router.POST("/user/login", handler.PostLoginHandler)
	router.GET("/user/libraryinfo", handler.GetLibraryInfoHandler)
	router.GET("/user/getbookinfo", handler.GetBookInfoHandler)
	router.POST("/user/request", AuthMiddleware.AuthMiddlewareUser(), handler.PostRequestHandler)
	router.GET("/user/requestinfo/:id", AuthMiddleware.AuthMiddlewareUser(), handler.GetConfirmFromAdminHandler)
	router.POST("/user/returnbook", AuthMiddleware.AuthMiddlewareUser(), handler.ReturnBookHandler)
	router.GET("/user/getlistlendbook/:id", AuthMiddleware.AuthMiddlewareUser(), handler.GetListLendBook)
	router.GET("/user/extendreturnbook/:id", AuthMiddleware.AuthMiddlewareUser(), handler.PostExtendBookHandler)
	router.GET("/user/:id", AuthMiddleware.AuthMiddlewareUser(), handler.GetProfileUserHandler)

	router.POST("/admin/signup", handler.PostSignupHandlerAdmin)
	router.POST("/admin/login", handler.PostLoginHandlerAdmin)
	router.POST("/admin/addbook", AuthMiddleware.AuthMiddlewareAdmin(), handler.PostAddBookHandler)
	router.PATCH("/admin/editbook/:id", AuthMiddleware.AuthMiddlewareAdmin(), handler.PatchEditBookHandler)
	router.DELETE("/admin/deletebook/:id", AuthMiddleware.AuthMiddlewareAdmin(), handler.DeleteBookHandler)
	router.GET("/admin/profile/:id", AuthMiddleware.AuthMiddlewareAdmin(), handler.GetProfileHandler)
	router.GET("/admin/getrequest/:id", AuthMiddleware.AuthMiddlewareAdmin(), handler.GetRequestHandler)
	router.POST("/admin/confirm", AuthMiddleware.AuthMiddlewareAdmin(), handler.PostConfirmHandler)
	router.POST("/admin/payment", AuthMiddleware.AuthMiddlewareAdmin(), handler.PostPaymentHandler)
	router.Run(":5000")
}
