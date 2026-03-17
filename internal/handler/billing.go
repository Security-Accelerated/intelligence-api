package handler

import (
	_ "embed"
	"html/template"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

//go:embed checkout_success.html
var checkoutSuccessHTML string

var checkoutSuccessTmpl = template.Must(template.New("checkout_success").Parse(checkoutSuccessHTML))

type checkoutSuccessData struct {
	APIKey     string
	Plan       string
	Error      string
	PortalLink string
}

// StripeWebhook handles incoming Stripe webhook events.
func (h *Handler) StripeWebhook(c *gin.Context) {
	payload, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	sigHeader := c.GetHeader("Stripe-Signature")
	if sigHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing Stripe-Signature header"})
		return
	}

	if err := h.billingService.HandleWebhook(c.Request.Context(), payload, sigHeader); err != nil {
		logging.Logger().Error("stripe webhook error",
			zap.Error(err),
			zap.String("client_ip", c.ClientIP()),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "webhook processing failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"received": true})
}

// CheckoutSuccess renders the success page showing the provisioned API key.
func (h *Handler) CheckoutSuccess(c *gin.Context) {
	sessionID := c.Query("session_id")
	if sessionID == "" {
		renderCheckoutError(c, "Missing session ID. Please use the link from your checkout confirmation.")
		return
	}

	rawKey, err := h.billingService.GetProvisionedKey(c.Request.Context(), sessionID)
	if err != nil {
		logging.Logger().Warn("provisioned key retrieval failed",
			zap.Error(err),
			zap.String("session_id", sessionID),
		)
		renderCheckoutError(c, "This API key has already been retrieved or the session has expired. If you did not save your key, please contact support@securityaccelerated.com.")
		return
	}

	var portalLink string
	if h.cfg != nil {
		portalLink = h.cfg.GetString("stripe.portal_link")
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
	checkoutSuccessTmpl.Execute(c.Writer, checkoutSuccessData{
		APIKey:     rawKey,
		Plan:       "paid",
		PortalLink: portalLink,
	})
}

func renderCheckoutError(c *gin.Context, msg string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
	checkoutSuccessTmpl.Execute(c.Writer, checkoutSuccessData{Error: msg})
}
