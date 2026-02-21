package main

import (
  "os"

  "github.com/vignesh07/babyshark/internal/app"
)

func main() {
  code := app.Run(os.Args[1:])
  os.Exit(code)
}
