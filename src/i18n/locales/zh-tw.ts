export const zhTW = {
  attachmentCollector: {
    confirm: '是否要遞迴收集下列資料夾中所有筆記的附件？\n{{folders}}\n此操作無法復原。',
    progressBar: {
      message: '正在收集附件 {{iterationString}} - \'{{noteFilePath}}\'.',
      title: '正在收集附件...'
    }
  },
  buttons: {
    copy: '複製',
    move: '移動',
    previewAttachmentFile: '預覽附件檔案',
    skip: '跳過'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: '附件 {{attachment}} 被多個筆記引用。',
    heading: '正在收集被多個筆記使用的附件',
    noPriorityWinnerReason: {
      EmptyList: '未移動，因為 {{settingName}} 設定為空，沒有依據判斷這些筆記中哪一個擁有它。',
      NoMatch: '未移動，因為這些筆記均不符合 {{settingName}} 設定中的任何項目。',
      Tie: '未移動，因為這些筆記中有多個與 {{settingName}} 設定的符合程度相同，無法確定唯一的擁有者。'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: '應該對其他有問題的附件使用相同操作'
  },
  commands: {
    collectAttachmentsCurrentFolder: '收集當前資料夾中的附件',
    collectAttachmentsCurrentNote: '收集當前筆記中的附件',
    collectAttachmentsEntireVault: '收集整個庫中的附件'
  },
  links: {
    documentation: '官方文件',
    tokens: '令牌'
  },
  menuItems: {
    collectAttachmentsInFile: '在檔案中收集附件',
    collectAttachmentsInFiles: '在多個檔案中收集附件'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: '正在為 \'{{noteFilePath}}\' 收集附件',
    collectingAttachmentsCancelled: '附件收集已取消。詳情請查看控制台。',
    generatedAttachmentFileNameIsInvalid: '生成的附件檔案名稱 \'{{path}}\' 無效。\n{{validationMessage}}\n請檢查您的 {{settingName}} 設定。',
    notePathIsIgnored: '筆記路徑已被忽略'
  },
  obsidianLib: {
    buttons: {
      cancel: '取消',
      ok: '確定'
    },
    dataview: {
      itemsPerPage: '每頁項目：',
      jumpToPage: '跳轉到頁面：'
    },
    notices: {
      attachmentIsStillUsed: '附件 {{attachmentPath}} 仍被其他筆記使用。不會被刪除。',
      unhandledError: '發生未處理的錯誤。請查看控制台以獲取更多信息。'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: '所有檔案都會重新命名。',
        displayText: '全部'
      },
      none: {
        description: '保留其名稱。',
        displayText: '無'
      },
      onlyPastedImages: {
        description: '僅重新命名貼上的圖片。僅適用於直接從剪貼簿貼上 PNG 圖片內容時。通常用於貼上截圖。',
        displayText: '僅貼上的圖片'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: '取消附件收集。',
        displayText: '取消'
      },
      copy: {
        description: '將附件複製到新位置。',
        displayText: '複製'
      },
      move: {
        description: '將附件移動到新位置。',
        displayText: '移動'
      },
      prompt: {
        description: '提示用戶選擇操作。',
        displayText: '提示'
      },
      skip: {
        description: '跳過此附件並繼續下一個。',
        displayText: '跳過'
      }
    },
    defaultImageSizeDimension: {
      height: '高度',
      width: '寬度'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// 自訂令牌因需更新為插件 9.0.0 版本所引入的新格式而被註解。\n// 詳情請參考官方文件 ({{customTokensDocumentationUrl}})。',
      deprecated: '自訂令牌的註冊格式已變更。請據此更新您的令牌。詳情請參閱{{documentation}}。'
    },
    legacyRenameAttachmentsToLowerCase: '{{setting}} 設定已被淘汰。請改用 {{format}} 格式。詳情請參閱{{documentation}}。',
    markdownUrlFormat: {
      deprecated: '您為 {{setting}} 格式設定的值可能不正確。詳情請參閱{{documentation}}。此訊息將不再顯示。'
    },
    specialCharacters: '{{setting}} 設定的預設值已變更。您的設定值已更新為新的預設值。',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: '預設圖片大小必須是像素或百分比',
      invalidCustomTokensCode: '無效的自訂令牌代碼',
      invalidRegularExpression: '無效的正則表達式 {{regExp}}',
      specialCharactersMustNotContainSlash: '特殊字元不得包含 /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: '特殊字元的替換不得包含無效的檔名或路徑字元。'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: '附加檔案時：',
      name: '附件重新命名模式'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: '當收集的附件被多個筆記使用時：',
      name: '多筆記共用附件收集模式'
    },
    collectedAttachmentFileName: {
      description: '參見可用的{{tokens}}。\n留空以保留附件目前的檔案名稱。',
      name: '收集的附件檔案名稱'
    },
    customTokens: {
      description: '要使用的自訂令牌。\n詳情請參閱{{documentation}}。\n⚠️ 自訂令牌可以是任意 JavaScript 代碼。若撰寫不當，可能導致資料遺失。使用風險請自行承擔。',
      name: '自訂令牌'
    },
    defaultImageSize: {
      description: '預設圖片大小。\n可以用像素（{{pixels}}）或圖片完整大小的百分比（{{percentage}}）指定。\n留空以使用原始圖片大小。',
      name: '預設圖片大小'
    },
    duplicateNameSeparator: {
      description: '當您貼上或拖曳一個與現有檔案同名的檔案時，此分隔符會加在檔案名稱中。\n例如，當您拖曳檔案 {{existingFile}} 時，它會被重新命名為 {{firstAvailableName}}、{{secondAvailableName}} 等，取第一個可用的名稱。',
      name: '重複名稱分隔符'
    },
    excludePathsFromAttachmentCollecting: {
      description: '執行 {{command}} 指令時，排除下列路徑中的附件。\n每條路徑請另起一行。\n{{pathSyntax}}\n若設定為空，收集附件時不排除任何路徑。',
      name: '收集附件排除路徑'
    },
    generatedAttachmentFileName: {
      description: '參見可用的{{tokens}}。',
      name: '產生的附件檔案名稱'
    },
    jpegQuality: {
      description: '品質越低，壓縮比越高。',
      name: 'JPEG 品質'
    },
    locationForNewAttachments: {
      description: '以 {{relativePrefix}} 開頭表示相對於筆記所在資料夾的路徑。\n參見可用的{{tokens}}。\n不建議使用 {{dotFolder}} 這類以點開頭的資料夾，因為 Obsidian 不會追蹤它們。您可能需要使用 {{unhidePlugin}} 外掛來管理它們。',
      name: '新附件位置'
    },
    markdownUrlFormat: {
      description: '新增附件時插入 Markdown 的 URL 格式。它只在插入當下套用：之後筆記或附件被重新命名或移動時，Obsidian 重寫的連結會使用預設格式。\n參見可用的{{tokens}}。\n留空以使用預設格式。',
      name: 'Markdown URL 格式'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: '是否將附件資料夾與檔案名稱設定套用至其他外掛建立的附件。\n有些外掛不詢問 Obsidian 附件該放在哪裡，逕自以自己的命名把附件寫入儲存庫。啟用此項後，這類檔案一出現就會被移動並重新命名。\n僅處理在筆記開啟時建立、且有筆記連結到的檔案：沒有任何筆記連結的檔案是其他外掛自用的資料，會留在寫入的位置。來自同步或儲存庫匯入的檔案絕不會被處理。\n{{modes}}\n建立檔案的外掛是根據寫入操作的呼叫堆疊來辨識，這只能盡力而為：由 Obsidian 本身、同步用戶端或延後寫入的外掛所寫入的檔案，無法辨識出外掛。這類檔案視為不在下方清單中。',
      name: '重新命名其他外掛建立的附件'
    },
    renameAttachmentsToLowerCase: '將附件名稱改成小寫',
    renamedAttachmentFileName: {
      description: '參見可用的{{tokens}}。\n留空以保留附件目前的檔案名稱。',
      name: '重新命名的附件檔案名稱'
    },
    resetToSampleCustomTokens: {
      message: '您確定要重設自訂令牌為範例令牌嗎？您的更改將會遺失。',
      title: '重設為範例令牌'
    },
    shouldConvertPastedImagesToJpeg: {
      description: '是否轉換貼上的圖片為 JPEG。僅在 PNG 圖片內容直接從剪貼簿貼上時適用。通常用於貼上截圖。',
      name: '是否轉換貼上的圖片為 JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: '啟用時，透過 {{command}} 指令處理的附件將根據 {{setting}} 設定重新命名。',
      name: '重新命名收集的附件'
    },
    specialCharacters: {
      description: '附件資料夾和檔案名稱中要替換或移除的特殊字元。\n留空以保留特殊字元。',
      name: '特殊字元'
    },
    specialCharactersReplacement: {
      description: '附件資料夾和檔案名稱中特殊字元的替換字串。\n留空以刪除特殊字元。',
      name: '特殊字元替換'
    },
    timeoutInSeconds: {
      description: '所有操作的逾時秒數。\n若設定為 {{zero}}，將停用操作執行逾時。',
      name: '逾時秒數'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: '重新命名附件檔案',
    folderTitle: '選擇附件資料夾',
    previewModal: {
      title: '預覽附件檔案 \'{{fullFileName}}\''
    },
    title: '提供提示令牌的值'
  },
  regularExpression: '/正則表達式/'
};
