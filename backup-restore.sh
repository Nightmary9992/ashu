#!/bin/bash

BACKUP_NAME="vps_backup.tar.gz"
BACKUP_URL="https://transfer.sh/vps_backup.tar.gz"

function restore_backup() {
  echo "🔄 Restoring backup..."
  curl -s -o $BACKUP_NAME $BACKUP_URL || {
    echo "⚠️ No previous backup found, starting fresh."
    return 1
  }

  tar -xzf $BACKUP_NAME || {
    echo "❌ Failed to extract backup."
    return 1
  }

  echo "✅ Backup restored."
}

function back_up_and_upload() {
  echo "📦 Creating backup and uploading..."
  # Change these folders to whatever you want backed up
  tar -czf $BACKUP_NAME ./data ./scripts ./.config 2>/dev/null || {
    echo "⚠️ Nothing to backup or folders do not exist."
    return 1
  }

  UPLOAD_LINK=$(curl --upload-file $BACKUP_NAME https://transfer.sh/$BACKUP_NAME)
  echo "✅ Backup uploaded: $UPLOAD_LINK"
  echo $UPLOAD_LINK > last_backup_url.txt
}

# Accept argument: restore_backup or back_up_and_upload
if [ "$1" == "restore_backup" ]; then
  restore_backup
elif [ "$1" == "back_up_and_upload" ]; then
  back_up_and_upload
else
  echo "Usage: $0 [restore_backup|back_up_and_upload]"
fi
