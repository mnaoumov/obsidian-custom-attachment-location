export const ja = {
  attachmentCollector: {
    confirm: '次のフォルダ内のすべてのノートの添付ファイルを再帰的に収集しますか？\n{{folders}}\nこの操作は元に戻せません。',
    progressBar: {
      message: '添付ファイルを収集中 {{iterationString}} - \'{{noteFilePath}}\'.',
      title: '添付ファイルを収集中...'
    }
  },
  buttons: {
    copy: 'コピー',
    move: '移動',
    previewAttachmentFile: '添付ファイルのプレビュー',
    skip: 'スキップ'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: '添付ファイル {{attachment}} が複数のノートで参照されています。',
    heading: '複数のノートで使用されている添付ファイルの収集',
    noPriorityWinnerReason: {
      EmptyList: '{{settingName}} 設定が空のため移動されませんでした。これらのノートのどれが所有するかを決めるものがありません。',
      NoMatch: 'これらのノートのいずれも {{settingName}} 設定のどの項目にも一致しないため、移動されませんでした。',
      Tie: 'これらのノートのうち複数が {{settingName}} 設定に同程度に一致するため、単一の所有者が決まらず、移動されませんでした。'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: '他の問題のある添付ファイルにも同じアクションを使用すべき'
  },
  commands: {
    collectAttachmentsCurrentFolder: '現在のフォルダの添付ファイルを収集',
    collectAttachmentsCurrentNote: '現在のノートの添付ファイルを収集',
    collectAttachmentsEntireVault: 'ボルト全体の添付ファイルを収集'
  },
  links: {
    documentation: 'ドキュメント',
    tokens: 'トークン'
  },
  menuItems: {
    collectAttachmentsInFile: 'ファイル内の添付ファイルを収集',
    collectAttachmentsInFiles: '複数ファイル内の添付ファイルを収集'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: '\'{{noteFilePath}}\'の添付ファイルを収集中',
    collectingAttachmentsCancelled: '添付ファイルの収集がキャンセルされました。詳細はコンソールを確認してください。',
    generatedAttachmentFileNameIsInvalid: '生成された添付ファイル名 \'{{path}}\' が無効です。\n{{validationMessage}}\n{{settingName}} 設定を確認してください。',
    notePathIsIgnored: 'ノートパスが無視されています'
  },
  obsidianLib: {
    buttons: {
      cancel: 'キャンセル',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'ページあたりの項目数:',
      jumpToPage: 'ページにジャンプ:'
    },
    notices: {
      attachmentIsStillUsed: '添付ファイル {{attachmentPath}} は他のノートでまだ使用されています。削除されません。',
      unhandledError: '未処理のエラーが発生しました。詳細についてはコンソールを確認してください。'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'すべてのファイルがリネームされます。',
        displayText: 'すべて'
      },
      none: {
        description: '名前が保持されます。',
        displayText: 'なし'
      },
      onlyPastedImages: {
        description: '貼り付けた画像のみがリネームされます。PNG画像の内容がクリップボードから直接貼り付けられた場合にのみ適用されます。通常、スクリーンショットの貼り付けに使用されます。',
        displayText: '貼り付けた画像のみ'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: '添付ファイルの収集をキャンセルします。',
        displayText: 'キャンセル'
      },
      copy: {
        description: '添付ファイルを新しい場所にコピーします。',
        displayText: 'コピー'
      },
      move: {
        description: '添付ファイルを新しい場所に移動します。',
        displayText: '移動'
      },
      prompt: {
        description: 'ユーザーにアクションを選択するよう促します。',
        displayText: 'プロンプト'
      },
      skip: {
        description: '添付ファイルをスキップして次のファイルに進みます。',
        displayText: 'スキップ'
      }
    },
    defaultImageSizeDimension: {
      height: '高さ',
      width: '幅'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// カスタムトークンは、プラグイン バージョン 9.0.0 で導入された新しい形式に更新する必要があるため、コメントアウトされました。\n// 詳細については、ドキュメント ({{customTokensDocumentationUrl}}) を参照してください。',
      deprecated: 'カスタムトークン登録の形式が変更されました。トークンを適切に更新してください。詳細については{{documentation}}を参照してください。'
    },
    legacyRenameAttachmentsToLowerCase: '{{setting}} 設定は非推奨です。代わりに {{format}} 形式を使用してください。詳細については{{documentation}}を参照してください。',
    markdownUrlFormat: {
      deprecated: '{{setting}} 形式に正しくない可能性のある値が設定されています。詳細については{{documentation}}を参照してください。このメッセージは再度表示されません。'
    },
    specialCharacters: '{{setting}} 設定のデフォルト値が変更されました。設定値は新しいデフォルト値に更新されました。',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'デフォルトの画像サイズはピクセルまたはパーセンテージで指定する必要があります',
      invalidCustomTokensCode: '無効なカスタムトークンコード',
      invalidRegularExpression: '無効な正規表現 {{regExp}}',
      specialCharactersMustNotContainSlash: '特殊文字には / を含めることはできません',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: '特殊文字の置換には無効なファイル名パス文字を含めることはできません。'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'ファイルを添付するとき:',
      name: '添付ファイルリネームモード'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: '収集された添付ファイルが複数のノートで使用されているとき:',
      name: '複数のノートで使用される添付ファイル収集モード'
    },
    collectedAttachmentFileName: {
      description: '利用可能な{{tokens}}を参照してください。\n現在の添付ファイル名を保持する場合は空白のままにしてください。',
      name: '収集された添付ファイル名'
    },
    customTokens: {
      description: '使用するカスタムトークン。\n詳細については{{documentation}}を参照してください。\n⚠️ カスタムトークンは任意のJavaScriptコードにすることができます。不適切に記述された場合、データ損失を引き起こす可能性があります。自己責任で使用してください。',
      name: 'カスタムトークン'
    },
    defaultImageSize: {
      description: 'デフォルトの画像サイズです。\nピクセル（{{pixels}}）または画像全体のサイズに対するパーセンテージ（{{percentage}}）で指定できます。\n元の画像サイズを使用する場合は空欄にしてください。',
      name: 'デフォルトの画像サイズ'
    },
    duplicateNameSeparator: {
      description: '既存のファイルと同じ名前のファイルを貼り付けまたはドラッグすると、この区切り文字がファイル名に追加されます。\n例：ファイル {{existingFile}} をドラッグすると、{{firstAvailableName}}、{{secondAvailableName}} などのうち、最初に利用可能な名前にリネームされます。',
      name: '重複名区切り文字'
    },
    excludePathsFromAttachmentCollecting: {
      description: '{{command}} コマンドの実行時に、以下のパスにある添付ファイルを除外します。\n各パスを新しい行に挿入してください。\n{{pathSyntax}}\n設定が空の場合、添付ファイル収集から除外されるパスはありません。',
      name: '添付ファイル収集から除外するパス'
    },
    generatedAttachmentFileName: {
      description: '利用可能な{{tokens}}を参照してください。',
      name: '生成された添付ファイル名'
    },
    jpegQuality: {
      description: '品質が低いほど、圧縮率が高くなります。',
      name: 'JPEG品質'
    },
    locationForNewAttachments: {
      description: 'ノートの親フォルダからの相対パスにするには {{relativePrefix}} で始めてください。\n利用可能な{{tokens}}を参照してください。\n{{dotFolder}} のようなドットフォルダは、Obsidianが追跡しないため推奨されません。管理するには {{unhidePlugin}} プラグインが必要になる場合があります。',
      name: '新しい添付ファイルの場所'
    },
    markdownUrlFormat: {
      description: '添付ファイルを追加したときにMarkdownに挿入されるURLの形式。適用されるのはその時点のみです。後でノートや添付ファイルの名前変更や移動によってObsidianが書き換えるリンクには、デフォルトの形式が使われます。\n利用可能な{{tokens}}を参照してください。\nデフォルト形式を使用するには空白のままにしてください。',
      name: 'Markdown URL形式'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: '他のプラグインが作成した添付ファイルにも、添付フォルダーとファイル名の設定を適用するかどうか。\n一部のプラグインは、どこに置くべきかを Obsidian に尋ねることなく、独自の名前で添付ファイルを直接保管庫に書き込みます。これを有効にすると、そのようなファイルは出現した直後に移動され、名前が変更されます。\n対象は、ノートを開いている間に作成され、かつノートからリンクされているファイルのみです。どのノートからもリンクされていないファイルは他のプラグインが自分用に保持するデータであり、書き込まれた場所に残ります。同期や保管庫の取り込みで届いたファイルは決して変更されません。\n{{modes}}\n作成元のプラグインは、書き込み時のコールスタックから特定されます。これはベストエフォートです。Obsidian 自身、同期クライアント、または書き込みを遅延させるプラグインが書き込んだファイルについては、プラグインが特定されません。そのようなファイルは、下のリストに含まれて「いない」ものとして扱われます。',
      name: '他のプラグインが作成した添付ファイルの名前を変更'
    },
    renameAttachmentsToLowerCase: '添付ファイルを小文字にリネーム',
    renamedAttachmentFileName: {
      description: '利用可能な{{tokens}}を参照してください。\n現在の添付ファイル名を保持する場合は空白のままにしてください。',
      name: 'リネームされた添付ファイル名'
    },
    resetToSampleCustomTokens: {
      message: 'カスタムトークンをサンプルカスタムトークンにリセットしてもよろしいですか？変更は失われます。',
      title: 'サンプルカスタムトークンにリセット'
    },
    shouldConvertPastedImagesToJpeg: {
      description: '貼り付けた画像をJPEGに変換するかどうか。PNG画像の内容がクリップボードから直接貼り付けられた場合にのみ適用されます。通常、スクリーンショットの貼り付けに使用されます。',
      name: '貼り付けた画像をJPEGに変換する'
    },
    shouldRenameCollectedAttachments: {
      description: '有効にすると、{{command}} コマンドで処理された添付ファイルは {{setting}} 設定に従ってリネームされます。',
      name: '収集された添付ファイルをリネームする'
    },
    specialCharacters: {
      description: '添付ファイルのフォルダ名とファイル名で置換または削除する特殊文字。\n特殊文字を保持するには空白のままにしてください。',
      name: '特殊文字'
    },
    specialCharactersReplacement: {
      description: '添付ファイルのフォルダ名とファイル名に含まれる特殊文字の置換文字列。\n特殊文字を削除するには空白のままにしてください。',
      name: '特殊文字の置換'
    },
    timeoutInSeconds: {
      description: 'すべての操作のタイムアウト（秒）。\n{{zero}} を設定すると、操作の実行タイムアウトは無効になります。',
      name: 'タイムアウト（秒）'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: '添付ファイルの名前を変更',
    folderTitle: '添付フォルダーを選択',
    previewModal: {
      title: '添付ファイルのプレビュー \'{{fullFileName}}\''
    },
    title: 'プロンプトトークンの値を提供してください'
  },
  regularExpression: '/正規表現/'
};
