// Package recording mirrors live PTY traffic into asciinema v2 JSON,
// captures resize events and channel metadata, uploads completed
// recordings to S3, and POSTs the recording index entry to certd so it
// appears in the portal's sessions list.
package recording
