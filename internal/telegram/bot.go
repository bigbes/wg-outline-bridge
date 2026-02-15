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
	From      *User  `json:"from"`
	Chat      Chat   `json:"chat"`
	Text      string `json:"text"`
}

// User represents a Telegram user.
type User struct {
	ID int64 `json:"id"`
}

// Chat represents a Telegram chat.
type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

// ChatPhoto represents a Telegram chat photo.
type ChatPhoto struct {
	SmallFileID string `json:"small_file_id"`
}

// ChatInfo is the result of getChat, containing profile information.
type ChatInfo struct {
	ID        int64      `json:"id"`
	FirstName string     `json:"first_name"`
	LastName  string     `json:"last_name"`
	Username  string     `json:"username"`
	Photo     *ChatPhoto `json:"photo"`
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

// SendMessageHTML sends a text message with HTML parse mode.
func (b *Bot) SendMessageHTML(ctx context.Context, chatID int64, text string) error {
	return b.sendMessageTo(ctx, chatID, text, "HTML")
}

// BotCommand represents a bot command for setMyCommands.
type BotCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// SetMyCommands registers command autocompletion with Telegram.
func (b *Bot) SetMyCommands(ctx context.Context, commands []BotCommand) error {
	payload := struct {
		Commands []BotCommand `json:"commands"`
	}{Commands: commands}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/setMyCommands", b.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("setting commands: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// SetChatMenuButton sets the bot's menu button to open a Web App.
// If url is empty, the default menu button is restored.
func (b *Bot) SetChatMenuButton(ctx context.Context, url, text string) error {
	type menuButton struct {
		Type   string `json:"type"`
		Text   string `json:"text,omitempty"`
		WebApp *struct {
			URL string `json:"url"`
		} `json:"web_app,omitempty"`
	}

	var btn menuButton
	if url == "" {
		btn.Type = "default"
	} else {
		btn.Type = "web_app"
		btn.Text = text
		btn.WebApp = &struct {
			URL string `json:"url"`
		}{URL: url}
	}

	payload := struct {
		MenuButton menuButton `json:"menu_button"`
	}{MenuButton: btn}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/setChatMenuButton", b.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("setting menu button: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	return nil
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

// GetChat retrieves chat/user info by numeric ID or @username.
func (b *Bot) GetChat(ctx context.Context, chatID string) (*ChatInfo, error) {
	payload := struct {
		ChatID string `json:"chat_id"`
	}{ChatID: chatID}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/getChat", b.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting chat: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telegram API error: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		OK     bool     `json:"ok"`
		Result ChatInfo `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	if !result.OK {
		return nil, fmt.Errorf("telegram API returned ok=false")
	}

	return &result.Result, nil
}

// GetFileURL returns the download URL for a file_id.
func (b *Bot) GetFileURL(ctx context.Context, fileID string) (string, error) {
	payload := struct {
		FileID string `json:"file_id"`
	}{FileID: fileID}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/getFile", b.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("getting file: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("telegram API error: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			FilePath string `json:"file_path"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}

	return fmt.Sprintf("https://api.telegram.org/file/bot%s/%s", b.token, result.Result.FilePath), nil
}
