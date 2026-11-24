export const ru = {
  attachmentCollector: {
    confirm: 'Собрать вложения для всех заметок в папках (рекурсивно)?\n{{folders}}\nЭту операцию нельзя отменить.',
    progressBar: {
      message: 'Сбор вложений {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Сбор вложений...'
    }
  },
  buttons: {
    copy: 'Копировать',
    move: 'Переместить',
    previewAttachmentFile: 'Предпросмотр файла вложения',
    skip: 'Пропустить'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Вложение {{attachment}} используется несколькими заметками.',
    heading: 'Сбор вложения, используемого несколькими заметками',
    noPriorityWinnerReason: {
      EmptyList: 'Он не был перемещён, поскольку настройка {{settingName}} пуста, поэтому ничто не определяет, какой из этих заметок он принадлежит.',
      NoMatch: 'Он не был перемещён, поскольку ни одна из этих заметок не соответствует ни одной записи в настройке {{settingName}}.',
      Tie: 'Он не был перемещён, поскольку несколько из этих заметок одинаково соответствуют настройке {{settingName}}, поэтому она не называет единственного владельца.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Использовать то же действие для других проблемных вложений'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Собрать вложения в текущей папке',
    collectAttachmentsCurrentNote: 'Собрать вложения в текущей заметке',
    collectAttachmentsEntireVault: 'Собрать вложения во всём хранилище'
  },
  links: {
    documentation: 'документацию',
    tokens: 'токены'
  },
  menuItems: {
    collectAttachmentsInFile: 'Собрать вложения в файле',
    collectAttachmentsInFiles: 'Собрать вложения в файлах'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Сбор вложений для \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Сбор вложений отменён. См. консоль для подробностей.',
    generatedAttachmentFileNameIsInvalid: 'Сгенерированное имя файла вложения \'{{path}}\' недопустимо.\n{{validationMessage}}\nПроверьте настройку {{settingName}}.',
    notePathIsIgnored: 'Путь заметки игнорируется'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Отменить',
      ok: 'ОК'
    },
    dataview: {
      itemsPerPage: 'Элементов на страницу:',
      jumpToPage: 'Перейти к странице:'
    },
    notices: {
      attachmentIsStillUsed: 'Вложение {{attachmentPath}} всё ещё используется другими заметками. Оно не будет удалено.',
      unhandledError: 'Произошла необработанная ошибка. Проверьте консоль для получения дополнительной информации.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'все файлы переименовываются.',
        displayText: 'Все'
      },
      none: {
        description: 'их имена сохраняются.',
        displayText: 'Ничего'
      },
      onlyPastedImages: {
        description: 'только вставленные изображения переименовываются. Применяется только когда содержимое PNG-изображения вставляется напрямую из буфера обмена. Обычно для вставки скриншотов.',
        displayText: 'Только вставленные изображения'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'отменить сбор вложений.',
        displayText: 'Отмена'
      },
      copy: {
        description: 'скопировать вложение в новое место.',
        displayText: 'Копировать'
      },
      move: {
        description: 'переместить вложение в новое место.',
        displayText: 'Переместить'
      },
      prompt: {
        description: 'запросить у пользователя выбор действия.',
        displayText: 'Запросить'
      },
      skip: {
        description: 'пропустить вложение и перейти к следующему.',
        displayText: 'Пропустить'
      }
    },
    defaultImageSizeDimension: {
      height: 'Высота',
      width: 'Ширина'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Пользовательские токены были закомментированы, так как их нужно обновить до нового формата, введённого в версии 9.0.0 плагина.\n// Обратитесь к документации ({{customTokensDocumentationUrl}}) для получения дополнительной информации.',
      deprecated: 'Формат регистрации пользовательских токенов изменился. Обновите ваши токены соответствующим образом. Подробнее см. {{documentation}}.'
    },
    legacyRenameAttachmentsToLowerCase: 'Настройка {{setting}} устарела. Используйте вместо неё формат {{format}}. Подробнее см. {{documentation}}.',
    markdownUrlFormat: {
      deprecated: 'Для формата {{setting}} установлено потенциально некорректное значение. Подробнее см. {{documentation}}. Это сообщение больше не будет показано.'
    },
    specialCharacters: 'Значение по умолчанию для настройки {{setting}} было изменено. Ваше значение обновлено до нового значения по умолчанию.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Размер изображения по умолчанию должен быть в пикселях или процентах',
      invalidCustomTokensCode: 'Неверный код пользовательских токенов',
      invalidRegularExpression: 'Неверное регулярное выражение {{regExp}}',
      specialCharactersMustNotContainSlash: 'Специальные символы не должны содержать /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Замена специальных символов не должна содержать недопустимые символы для пути файла.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'При добавлении файлов:',
      name: 'Режим переименования вложений'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Когда собираемое вложение используется несколькими заметками:',
      name: 'Режим сбора вложений, используемых несколькими заметками'
    },
    collectedAttachmentFileName: {
      description: 'См. доступные {{tokens}}.\nОставьте пустым, чтобы сохранить текущее имя файла вложения.',
      name: 'Собранное имя файла вложения'
    },
    customTokens: {
      description: 'Пользовательские токены для использования.\nПодробнее см. {{documentation}}.\n⚠️ Пользовательские токены могут содержать произвольный JavaScript-код. Если он написан неверно, это может привести к потере данных. Используйте на свой риск.',
      name: 'Пользовательские токены'
    },
    defaultImageSize: {
      description: 'Размер изображения по умолчанию.\nМожно указать в пикселях ({{pixels}}) или в процентах от полного размера изображения ({{percentage}}).\nОставьте пустым, чтобы использовать оригинальный размер изображения.',
      name: 'Размер изображения по умолчанию'
    },
    duplicateNameSeparator: {
      description: 'Если вставляется или перетаскивается файл с тем же именем, что и у существующего, к имени файла будет добавлен этот разделитель.\nНапример, при перетаскивании файла {{existingFile}} он будет переименован в {{firstAvailableName}}, {{secondAvailableName}} и т. д. — берётся первое свободное имя.',
      name: 'Разделитель для дубликатов имён'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Исключить вложения из следующих путей при выполнении команды {{command}}.\nУказывайте каждый путь на новой строке.\n{{pathSyntax}}\nЕсли настройка пуста, ни один путь не исключается из сбора вложений.',
      name: 'Исключить пути из сбора вложений'
    },
    generatedAttachmentFileName: {
      description: 'См. доступные {{tokens}}.',
      name: 'Сгенерированное имя файла вложения'
    },
    jpegQuality: {
      description: 'Чем ниже качество, тем выше степень сжатия.',
      name: 'Качество JPEG'
    },
    locationForNewAttachments: {
      description: 'Начинайте с {{relativePrefix}}, чтобы указать путь относительно родительской папки заметки.\nСм. доступные {{tokens}}.\nПапки с точкой, такие как {{dotFolder}}, не рекомендуются, так как Obsidian их не отслеживает. Для работы с ними может понадобиться плагин {{unhidePlugin}}.',
      name: 'Расположение для новых вложений'
    },
    markdownUrlFormat: {
      description: 'Формат URL, который вставляется в Markdown при добавлении вложения. Он применяется только в этот момент: ссылка, которую Obsidian перепишет позже, при переименовании или перемещении заметки или вложения, получит формат по умолчанию.\nСм. доступные {{tokens}}.\nОставьте пустым, чтобы использовать формат по умолчанию.',
      name: 'Формат URL для Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Применять ли настройки папки вложений и имени файла к вложениям, которые создают ДРУГИЕ плагины.\nНекоторые плагины записывают вложение в хранилище под собственным именем, не спрашивая Obsidian, где ему место. Если включено, такой файл перемещается и переименовывается сразу после появления.\nЗатрагиваются только файлы, созданные при открытой заметке, на которые ссылается заметка: файл, на который не ссылается ни одна заметка, — это данные, которые другой плагин хранит для себя, и он остаётся там, где был записан. Файлы, пришедшие из синхронизации или импорта хранилища, никогда не затрагиваются.\n{{modes}}\nПлагин, создавший файл, определяется по стеку вызовов записи. Это делается по мере возможности: плагин не определяется для файла, записанного самим Obsidian, клиентом синхронизации или плагином, который откладывает запись. Такой файл считается НЕ входящим в список ниже.',
      name: 'Переименовывать вложения, созданные другими плагинами'
    },
    renameAttachmentsToLowerCase: 'Переименовывать вложения строчными буквами',
    renamedAttachmentFileName: {
      description: 'См. доступные {{tokens}}.\nОставьте пустым, чтобы сохранить текущее имя файла вложения.',
      name: 'Переименованное имя файла вложения'
    },
    resetToSampleCustomTokens: {
      message: 'Вы уверены, что хотите сбросить пользовательские токены до образцов? Все ваши изменения будут потеряны.',
      title: 'Сбросить к образцам токенов'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Определяет, нужно ли конвертировать вставленные изображения в JPEG. Применяется только если PNG вставлен напрямую из буфера обмена. Обычно используется для скриншотов.',
      name: 'Конвертировать вставленные изображения в JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Если включено, вложения, обработанные командами {{command}}, будут переименованы в соответствии с настройкой {{setting}}.',
      name: 'Переименовывать собранные вложения'
    },
    specialCharacters: {
      description: 'Специальные символы в имени папки и файла вложения, которые будут заменены или удалены.\nОставьте пустым, чтобы сохранить специальные символы.',
      name: 'Специальные символы'
    },
    specialCharactersReplacement: {
      description: 'Строка для замены специальных символов в имени папки и файла вложения.\nОставьте пустым, чтобы удалить специальные символы.',
      name: 'Замена специальных символов'
    },
    timeoutInSeconds: {
      description: 'Таймаут в секундах для всех операций.\nЕсли установлено {{zero}}, ограничение времени выполнения операций отключается.',
      name: 'Таймаут в секундах'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Переименовать файл вложения',
    folderTitle: 'Выберите папку вложений',
    previewModal: {
      title: 'Предпросмотр файла вложения \'{{fullFileName}}\''
    },
    title: 'Введите значение для токена запроса'
  },
  regularExpression: '/регулярное выражение/'
};
