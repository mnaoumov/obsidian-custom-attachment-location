export const uk = {
  attachmentCollector: {
    confirm: 'Бажаєте рекурсивно зібрати вкладення для всіх нотаток у папках?\n{{folders}}\nЦю операцію неможливо скасувати.',
    progressBar: {
      message: 'Збирання вкладень {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Збирання вкладень...'
    }
  },
  buttons: {
    copy: 'Копіювати',
    move: 'Перемістити',
    previewAttachmentFile: 'Попередній перегляд вкладеного файлу',
    skip: 'Пропустити'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'На вкладення {{attachment}} посилаються кілька нотаток.',
    heading: 'Збирання вкладення, яке використовується кількома нотатками',
    noPriorityWinnerReason: {
      EmptyList: 'Його не було переміщено, оскільки налаштування {{settingName}} порожнє, тож ніщо не визначає, якій із цих нотаток він належить.',
      NoMatch: 'Його не було переміщено, оскільки жодна з цих нотаток не відповідає жодному запису в налаштуванні {{settingName}}.',
      Tie: 'Його не було переміщено, оскільки кілька із цих нотаток однаково відповідають налаштуванню {{settingName}}, тож воно не називає єдиного власника.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Використовувати ту саму дію для інших проблемних вкладень'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Зібрати вкладення в поточній папці',
    collectAttachmentsCurrentNote: 'Зібрати вкладення в поточній нотатці',
    collectAttachmentsEntireVault: 'Зібрати вкладення в усьому сховищі'
  },
  links: {
    documentation: 'документації',
    tokens: 'токени'
  },
  menuItems: {
    collectAttachmentsInFile: 'Зібрати вкладення у файлі',
    collectAttachmentsInFiles: 'Зібрати вкладення у файлах'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Збирання вкладень для \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Збирання вкладень скасовано. Дивіться консоль для деталей.',
    generatedAttachmentFileNameIsInvalid: 'Згенерована назва файлу вкладення \'{{path}}\' недійсна.\n{{validationMessage}}\nПеревірте налаштування {{settingName}}.',
    notePathIsIgnored: 'Шлях нотатки ігнорується'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Скасувати',
      ok: 'ОК'
    },
    dataview: {
      itemsPerPage: 'Елементів на сторінку:',
      jumpToPage: 'Перейти на сторінку:'
    },
    notices: {
      attachmentIsStillUsed: 'Вкладення {{attachmentPath}} все ще використовується іншими нотатками. Воно не буде видалено.',
      unhandledError: 'Сталася необроблена помилка. Будь ласка, перевірте консоль для отримання додаткової інформації.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'всі файли перейменовуються.',
        displayText: 'Всі'
      },
      none: {
        description: 'їхні назви зберігаються.',
        displayText: 'Жоден'
      },
      onlyPastedImages: {
        description: 'тільки вставлені зображення перейменовуються. Застосовується тільки коли контент PNG зображення вставляється безпосередньо з буфера обміну. Зазвичай, для вставки скріншотів.',
        displayText: 'Тільки вставлені зображення'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'скасувати збір вкладень.',
        displayText: 'Скасувати'
      },
      copy: {
        description: 'копіювати вкладення в нове місце.',
        displayText: 'Копіювати'
      },
      move: {
        description: 'перемістити вкладення в нове місце.',
        displayText: 'Перемістити'
      },
      prompt: {
        description: 'запитати користувача про вибір дії.',
        displayText: 'Запитати'
      },
      skip: {
        description: 'пропустити вкладення та перейти до наступного.',
        displayText: 'Пропустити'
      }
    },
    defaultImageSizeDimension: {
      height: 'Висота',
      width: 'Ширина'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Користувацькі токени були закоментовані, оскільки їх потрібно оновити до нового формату, введеного у версії 9.0.0 плагіна.\n// Див. документацію ({{customTokensDocumentationUrl}}).',
      deprecated: 'Формат реєстрації користувацьких токенів змінився. Будь ласка, оновіть свої токени відповідно. Докладніше читайте в {{documentation}}.'
    },
    legacyRenameAttachmentsToLowerCase: 'Налаштування {{setting}} застаріло. Натомість використовуйте формат {{format}}. Докладніше читайте в {{documentation}}.',
    markdownUrlFormat: {
      deprecated: 'Для формату {{setting}} встановлено, можливо, некоректне значення. Докладніше читайте в {{documentation}}. Це повідомлення більше не відображатиметься.'
    },
    specialCharacters: 'Значення налаштування {{setting}} за замовчуванням змінилося. Ваше значення оновлено до нового значення за замовчуванням.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Розмір зображення за замовчуванням має бути в пікселях або відсотках',
      invalidCustomTokensCode: 'Невірний код користувацьких токенів',
      invalidRegularExpression: 'Невірний регулярний вираз {{regExp}}',
      specialCharactersMustNotContainSlash: 'Спеціальні символи не повинні містити /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Заміна спеціальних символів не повинна містити недопустимі символи шляху або імені файлу.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Під час додавання файлів:',
      name: 'Режим перейменування вкладень'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Коли зібране вкладення використовується кількома нотатками:',
      name: 'Режим збору вкладень, які використовуються кількома нотатками'
    },
    collectedAttachmentFileName: {
      description: 'Див. доступні {{tokens}}.\nЗалиште порожнім, щоб зберегти поточну назву файлу вкладення.',
      name: 'Назва зібраного файлу вкладення'
    },
    customTokens: {
      description: 'Користувацькі токени для використання.\nДокладніше читайте в {{documentation}}.\n⚠️ Користувацькі токени можуть бути довільним кодом JavaScript. Погано написаний код може призвести до втрати даних. Використовуйте на власний ризик.',
      name: 'Користувацькі токени'
    },
    defaultImageSize: {
      description: 'Розмір зображення за замовчуванням.\nМожна вказати в пікселях ({{pixels}}) або у відсотках від повного розміру зображення ({{percentage}}).\nЗалиште порожнім, щоб використовувати оригінальний розмір зображення.',
      name: 'Розмір зображення за замовчуванням'
    },
    duplicateNameSeparator: {
      description: 'Коли ви вставляєте або перетягуєте файл із такою самою назвою, як в наявного файлу, до назви файлу буде додано цей роздільник.\nНаприклад, якщо ви перетягуєте файл {{existingFile}}, його буде перейменовано на {{firstAvailableName}}, {{secondAvailableName}} тощо, залежно від того, яка назва вільна першою.',
      name: 'Роздільник для дублікатів імен'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Не збирати вкладення з наступних шляхів під час виконання команди {{command}}.\nВведіть кожен шлях з нового рядка.\n{{pathSyntax}}\nЯкщо поле порожнє, жоден шлях не виключається зі збору вкладень.',
      name: 'Ігноровані шляхи при зборі вкладень'
    },
    generatedAttachmentFileName: {
      description: 'Див. доступні {{tokens}}.',
      name: 'Згенерована назва файлу вкладення'
    },
    jpegQuality: {
      description: 'Чим менша якість, тим більша компресія.',
      name: 'Якість JPEG'
    },
    locationForNewAttachments: {
      description: 'Почніть з {{relativePrefix}}, щоб шлях був відносним до батьківської папки нотатки.\nДив. доступні {{tokens}}.\nПапки з крапкою, як-от {{dotFolder}}, не рекомендуються, бо Obsidian їх не відстежує. Для керування ними може знадобитися плагін {{unhidePlugin}}.',
      name: 'Розташування нових вкладень'
    },
    markdownUrlFormat: {
      description: 'Формат URL, що вставляється в Markdown під час додавання вкладення. Він застосовується лише в цей момент: посилання, яке Obsidian переписує пізніше, коли нотатку чи вкладення перейменовують або переміщують, отримує формат за замовчуванням.\nДив. доступні {{tokens}}.\nЗалиште порожнім, щоб використовувати формат за замовчуванням.',
      name: 'Формат URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Чи застосовувати налаштування папки вкладень та назви файлу до вкладень, які створюють ІНШІ плагіни.\nДеякі плагіни записують вкладення до сховища під власною назвою, не питаючи в Obsidian, де йому місце. Якщо це ввімкнено, такий файл переміщується та перейменовується одразу після появи.\nЗачіпаються лише файли, створені за відкритої нотатки, на які посилається нотатка: файл, на який не посилається жодна нотатка, — це дані, які інший плагін зберігає для себе, тож він лишається там, де його записано. Файли, що надходять із синхронізації чи імпорту сховища, ніколи не зачіпаються.\n{{modes}}\nПлагін, що створив файл, визначається за стеком викликів запису. Це робиться за можливості: для файлу, записаного самим Obsidian, клієнтом синхронізації або плагіном, що відкладає запис, плагін не визначається. Такий файл вважається таким, якого НЕМАЄ в списку нижче.',
      name: 'Перейменовувати вкладення, створені іншими плагінами'
    },
    renameAttachmentsToLowerCase: 'Перейменовувати вкладення з маленьких літер',
    renamedAttachmentFileName: {
      description: 'Див. доступні {{tokens}}.\nЗалиште порожнім, щоб зберегти поточну назву файлу вкладення.',
      name: 'Назва перейменованого файлу вкладення'
    },
    resetToSampleCustomTokens: {
      message: 'Ви впевнені, що хочете скинути користувацькі токени до прикладу? Ваші зміни буде втрачено.',
      title: 'Скинути до прикладу'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Перетворювати вставлені зображення у JPEG. Застосовується лише, коли PNG вставлено безпосередньо з буфера обміну. Зазвичай для вставки скріншотів.',
      name: 'Конвертувати вставлені зображення у JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Якщо увімкнено, вкладення, оброблені командами {{command}}, буде перейменовано відповідно до налаштування {{setting}}.',
      name: 'Перейменовувати зібрані вкладення'
    },
    specialCharacters: {
      description: 'Спеціальні символи в назві папки та файлу вкладення, які треба замінити або видалити.\nЗалиште порожнім, щоб зберегти спеціальні символи.',
      name: 'Спеціальні символи'
    },
    specialCharactersReplacement: {
      description: 'Рядок заміни для спеціальних символів у назві папки та файлу вкладення.\nЗалиште порожнім, щоб видаляти спеціальні символи.',
      name: 'Заміна спеціальних символів'
    },
    timeoutInSeconds: {
      description: 'Тайм-аут у секундах для всіх операцій.\nЯкщо встановлено {{zero}}, тайм-аут виконання операцій вимкнено.',
      name: 'Тайм-аут в секундах'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Перейменувати файл вкладення',
    folderTitle: 'Виберіть папку вкладень',
    previewModal: {
      title: 'Попередній перегляд вкладеного файлу \'{{fullFileName}}\''
    },
    title: 'Введіть значення для токена запиту'
  },
  regularExpression: '/регулярний вираз/'
};
