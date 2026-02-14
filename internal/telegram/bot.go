package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Update represents a Telegram Bot API update.
type Update struct {
	UpdateID int64    `json:"update_id"`
	Message  *Message `json:"message"`
}

// Message represents a Telegram message.
type Message struct {
	MessageID int64  `json:"message_id"`
	Chat      Chat   `json:"chat"`
	Text      string `json:"text"`
}

// Chat represents a Telegram chat.
type Chat struct {
	ID int64 `json:"id"`
}

// Bot is a minimal Telegram Bot API client.
type Bot struct {
	token  string
	chatID int64
	client *http.Client
}

// NewBot creates a new Telegram bot client. If chatID is 0, push
// notifications via SendMessage are disabled (the bot can still
// respond to incoming commands via SendMessageTo).
func NewBot(token string, chatID int64) *Bot {
	return &Bot{
		token:  token,
		chatID: chatID,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

type sendMessageRequest struct {
	ChatID    int64  `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode,omitempty"`
}

// SendMessage sends a text message to the configured chat.
// It is a no-op if no chat_id was configured.
func (b *Bot) SendMessage(ctx context.Context, text string) error {
	if b.chatID == 0 {
		return nil
	}
	return b.sendMessageTo(ctx, b.chatID, text, "")
}

// SendMessageTo sends a text message to the specified chat.
func (b *Bot) SendMessageTo(ctx context.Context, chatID int64, text string) error {
	return b.sendMessageTo(ctx, chatID, text, "")
}

func (b *Bot) sendMessageTo(ctx context.Context, chatID int64, text, parseMode string) error {
	reqBody := sendMessageRequest{
		ChatID:    chatID,
		Text:      text,
		ParseMode: parseMode,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", b.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

type getUpdatesRequest struct {
	Offset  int64 `json:"offset"`
	Timeout int   `json:"timeout"`
}

type getUpdatesResponse struct {
	OK     bool     `json:"ok"`
	Result []Update `json:"result"`
}

// GetUpdates performs a long-poll request for new updates.
func (b *Bot) GetUpdates(ctx context.Context, offset int64, timeout int) ([]Update, error) {
	reqBody := getUpdatesRequest{
		Offset:  offset,
		Timeout: timeout,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates", b.token)
	// Use a longer HTTP timeout to accommodate the Telegram long-poll timeout.
	httpClient := &http.Client{Timeout: time.Duration(timeout+10) * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("polling updates: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telegram API error: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	var result getUpdatesResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return result.Result, nil
}
