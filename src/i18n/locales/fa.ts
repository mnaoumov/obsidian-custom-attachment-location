export const fa = {
  attachmentCollector: {
    confirm: 'آیا می‌خواهید پیوست‌های همهٔ یادداشت‌های پوشه‌های زیر را به‌صورت بازگشتی جمع‌آوری کنید؟\n{{folders}}\nاین عملیات قابل بازگشت نیست.',
    progressBar: {
      message: 'جمع‌آوری پیوست‌ها {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'در حال جمع‌آوری پیوست‌ها...'
    }
  },
  buttons: {
    copy: 'کپی',
    move: 'انتقال',
    previewAttachmentFile: 'پیش‌نمایش فایل پیوست',
    skip: 'رد کردن'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'پیوست {{attachment}} توسط چندین یادداشت ارجاع داده شده است.',
    heading: 'جمع‌آوری پیوست استفاده شده توسط چندین یادداشت',
    noPriorityWinnerReason: {
      EmptyList: 'منتقل نشد زیرا تنظیم {{settingName}} خالی است، بنابراین چیزی تعیین نمی‌کند که کدام یک از این یادداشت‌ها مالک آن است.',
      NoMatch: 'منتقل نشد زیرا هیچ‌یک از این یادداشت‌ها با هیچ ورودی در تنظیم {{settingName}} مطابقت ندارد.',
      Tie: 'منتقل نشد زیرا چند مورد از این یادداشت‌ها به یک اندازه با تنظیم {{settingName}} مطابقت دارند، بنابراین مالک واحدی تعیین نمی‌کند.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'از همان عملیات برای سایر پیوست‌های مشکل‌دار استفاده شود'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'جمع‌آوری پیوست‌ها در پوشه فعلی',
    collectAttachmentsCurrentNote: 'جمع‌آوری پیوست‌ها در یادداشت فعلی',
    collectAttachmentsEntireVault: 'جمع‌آوری پیوست‌ها در کل خزانه'
  },
  links: {
    documentation: 'مستندات',
    tokens: 'نشان‌های موجود'
  },
  menuItems: {
    collectAttachmentsInFile: 'جمع‌آوری پیوست‌ها در فایل',
    collectAttachmentsInFiles: 'جمع‌آوری پیوست‌ها در فایل‌ها'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'جمع‌آوری پیوست‌ها برای \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'جمع‌آوری پیوست‌ها لغو شد. برای جزئیات کنسول را ببینید.',
    generatedAttachmentFileNameIsInvalid: 'نام فایل پیوست تولید شده \'{{path}}\' نامعتبر است.\n{{validationMessage}}\nتنظیم {{settingName}} خود را بررسی کنید.',
    notePathIsIgnored: 'مسیر یادداشت نادیده گرفته شده است'
  },
  obsidianLib: {
    buttons: {
      cancel: 'لغو',
      ok: 'تأیید'
    },
    dataview: {
      itemsPerPage: 'آیتم در هر صفحه:',
      jumpToPage: 'رفتن به صفحه:'
    },
    notices: {
      attachmentIsStillUsed: 'پیوست {{attachmentPath}} هنوز توسط یادداشت‌های دیگر استفاده می‌شود. حذف نخواهد شد.',
      unhandledError: 'خطای غیرقابل مدیریت رخ داد. لطفاً کنسول را برای اطلاعات بیشتر بررسی کنید.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'همه فایل‌ها تغییر نام داده می‌شوند.',
        displayText: 'همه'
      },
      none: {
        description: 'نام‌های آن‌ها حفظ می‌شود.',
        displayText: 'هیچکدام'
      },
      onlyPastedImages: {
        description: 'فقط تصاویر قرارداده شده تغییر نام داده می‌شوند. فقط زمانی اعمال می‌شود که محتوای تصویر PNG مستقیماً از کلیپ‌بورد قرارداده شود. معمولاً برای قراردادن عکس‌های صفحه.',
        displayText: 'فقط تصاویر قرارداده شده'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'جمع‌آوری پیوست‌ها را لغو کند.',
        displayText: 'لغو'
      },
      copy: {
        description: 'پیوست را به مکان جدید کپی کند.',
        displayText: 'کپی'
      },
      move: {
        description: 'پیوست را به مکان جدید انتقال دهد.',
        displayText: 'انتقال'
      },
      prompt: {
        description: 'از کاربر بپرسد که عملیات مورد نظر را انتخاب کند.',
        displayText: 'پرسش'
      },
      skip: {
        description: 'پیوست را رد کند و به مورد بعدی برود.',
        displayText: 'رد کردن'
      }
    },
    defaultImageSizeDimension: {
      height: 'ارتفاع',
      width: 'عرض'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// نشان‌های سفارشی کامنت شده زیرا باید به فرمت جدید معرفی شده در نسخه 9.0.0 پلاگین به‌روزرسانی شوند.\n// برای اطلاعات بیشتر به مستندات ({{customTokensDocumentationUrl}}) مراجعه کنید.',
      deprecated: 'فرمت ثبت نشان‌های سفارشی تغییر کرده است. لطفاً نشان‌های خود را به تناسب به‌روزرسانی کنید. برای اطلاعات بیشتر به {{documentation}} مراجعه کنید.'
    },
    legacyRenameAttachmentsToLowerCase: 'تنظیم {{setting}} منسوخ شده است. به جای آن از فرمت {{format}} استفاده کنید. برای اطلاعات بیشتر به {{documentation}} مراجعه کنید.',
    markdownUrlFormat: {
      deprecated: 'ممکن است مقدار نادرستی برای فرمت {{setting}} تنظیم کرده باشید. لطفاً برای اطلاعات بیشتر به {{documentation}} مراجعه کنید. این پیام دیگر نشان داده نخواهد شد.'
    },
    specialCharacters: 'مقدار پیش‌فرض تنظیم {{setting}} تغییر کرده است. مقدار تنظیمات شما به مقدار پیش‌فرض جدید به‌روزرسانی شد.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'اندازه پیش‌فرض تصویر باید بر حسب پیکسل یا درصد باشد',
      invalidCustomTokensCode: 'کد نشان‌های سفارشی نامعتبر',
      invalidRegularExpression: 'عبارت قانونی نامعتبر {{regExp}}',
      specialCharactersMustNotContainSlash: 'کراکترهای ویژه نباید حاوی / باشند',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'جایگزین کراکترهای ویژه نباید حاوی کراکترهای نامعتبر مسیر نام فایل باشد.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'هنگام ضمیمه کردن فایل‌ها:',
      name: 'حالت تغییر نام پیوست'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'زمانی که پیوست جمع‌آوری شده توسط چندین یادداشت استفاده می‌شود:',
      name: 'حالت جمع‌آوری پیوست استفاده شده توسط چندین یادداشت'
    },
    collectedAttachmentFileName: {
      description: '{{tokens}} را ببینید.\nبرای حفظ نام فعلی فایل پیوست خالی بگذارید.',
      name: 'نام فایل پیوست جمع‌آوری شده'
    },
    customTokens: {
      description: 'نشان‌های سفارشی که استفاده خواهند شد.\nبرای اطلاعات بیشتر به {{documentation}} مراجعه کنید.\n⚠️ نشان‌های سفارشی می‌توانند کد JavaScript دلخواهی باشند. اگر بد نوشته شوند، می‌توانند باعث از دست رفتن داده‌ها شوند. به عهده خودتان استفاده کنید.',
      name: 'نشان‌های سفارشی'
    },
    defaultImageSize: {
      description: 'اندازه پیش‌فرض تصویر.\nمی‌تواند بر حسب پیکسل ({{pixels}}) یا بر حسب درصدی از اندازه کامل تصویر ({{percentage}}) مشخص شود.\nبرای استفاده از اندازه اصلی خالی بگذارید.',
      name: 'اندازه پیش‌فرض تصویر'
    },
    duplicateNameSeparator: {
      description: 'زمانی که فایلی هم‌نام با یک فایل موجود را قرار می‌دهید یا می‌کشید، این جداکننده به نام فایل افزوده خواهد شد.\nمثلاً، زمانی که فایل {{existingFile}} را می‌کشید، به {{firstAvailableName}}، {{secondAvailableName}} و غیره تغییر نام خواهد یافت، تا اولین نام موجود به دست آید.',
      name: 'جداکننده نام تکراری'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'پیوست‌های موجود در مسیرهای زیر را هنگام اجرای فرمان {{command}} نادیده بگیرید.\nهر مسیر را در یک خط جدید وارد کنید.\n{{pathSyntax}}\nاگر تنظیم خالی باشد، هیچ مسیری از جمع‌آوری پیوست نادیده گرفته نمی‌شود.',
      name: 'مسیرهای نادیده گرفته شده از جمع‌آوری پیوست'
    },
    generatedAttachmentFileName: {
      description: '{{tokens}} را ببینید.',
      name: 'نام فایل پیوست تولید شده'
    },
    jpegQuality: {
      description: 'هر چه کیفیت کمتر باشد، نسبت فشرده‌سازی بیشتر است.',
      name: 'کیفیت JPEG'
    },
    locationForNewAttachments: {
      description: 'برای مسیرهای نسبی به پوشهٔ والد یادداشت، با {{relativePrefix}} شروع کنید.\n{{tokens}} را ببینید.\nپوشه‌های نقطه‌ای مانند {{dotFolder}} توصیه نمی‌شوند، زیرا Obsidian آن‌ها را ردیابی نمی‌کند. ممکن است برای مدیریت آن‌ها به پلاگین {{unhidePlugin}} نیاز داشته باشید.',
      name: 'مکان پیوست‌های جدید'
    },
    markdownUrlFormat: {
      description: 'فرمت URL که هنگام افزودن پیوست در Markdown وارد خواهد شد. فقط در همان لحظه اعمال می‌شود: پیوندی که Obsidian بعداً، هنگام تغییر نام یا جابه‌جایی یک یادداشت یا پیوست، بازنویسی می‌کند، فرمت پیش‌فرض را می‌گیرد.\n{{tokens}} را ببینید.\nبرای استفاده از فرمت پیش‌فرض خالی بگذارید.',
      name: 'فرمت URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'اینکه تنظیمات پوشه پیوست و نام فایل بر پیوست‌هایی که افزونه‌های دیگر می‌سازند اعمال شود یا نه.\nبرخی افزونه‌ها پیوست را با نام دلخواه خود مستقیماً در گاوصندوق می‌نویسند، بدون آنکه از Obsidian بپرسند جای آن کجاست. با فعال بودن این گزینه، چنین فایلی بلافاصله پس از پدیدار شدن جابه‌جا و تغییر نام داده می‌شود.\nتنها فایل‌هایی تغییر می‌کنند که هنگام باز بودن یک یادداشت ساخته شده‌اند و یادداشتی به آن‌ها پیوند می‌دهد: فایلی که هیچ یادداشتی به آن پیوند نمی‌دهد، داده‌ای است که افزونه‌ای دیگر برای خود نگه می‌دارد و همان‌جا که نوشته شده می‌ماند. فایل‌های حاصل از همگام‌سازی یا درون‌ریزی گاوصندوق هرگز دست‌کاری نمی‌شوند.\n{{modes}}\nافزونهٔ سازنده از روی پشتهٔ فراخوانی عملیات نوشتن شناسایی می‌شود. این شناسایی فقط در حد امکان است: برای فایلی که خود Obsidian، یک کارخواه همگام‌سازی یا افزونه‌ای که نوشتن خود را به تعویق می‌اندازد می‌نویسد، هیچ افزونه‌ای شناسایی نمی‌شود. چنین فایلی جزو فهرست زیر به شمار نمی‌آید.',
      name: 'تغییر نام پیوست‌هایی که افزونه‌های دیگر می‌سازند'
    },
    renameAttachmentsToLowerCase: 'تغییر نام پیوست‌ها به حروف کوچک',
    renamedAttachmentFileName: {
      description: '{{tokens}} را ببینید.\nبرای حفظ نام فعلی فایل پیوست خالی بگذارید.',
      name: 'نام فایل پیوست تغییر نام یافته'
    },
    resetToSampleCustomTokens: {
      message: 'آیا مطمئن هستید که می‌خواهید نشان‌های سفارشی را به نشان‌های سفارشی نمونع بازنشانی کنید؟ تغییرات شما از دست خواهد رفت.',
      title: 'بازنشانی به نشان‌های سفارشی نمونه'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'آیا تصاویر قرارداده شده به JPEG تبدیل شوند. فقط زمانی اعمال می‌شود که محتوای تصویر PNG مستقیماً از کلیپ‌بورد قرارداده شود. معمولاً برای قراردادن عکس‌های صفحه.',
      name: 'آیا تصاویر قرارداده شده به JPEG تبدیل شوند'
    },
    shouldRenameCollectedAttachments: {
      description: 'اگر فعال باشد، پیوست‌هایی که با فرمان‌های {{command}} پردازش می‌شوند، بر اساس تنظیم {{setting}} تغییر نام خواهند یافت.',
      name: 'آیا پیوست‌های جمع‌آوری شده تغییر نام پیدا کنند'
    },
    specialCharacters: {
      description: 'کراکترهای ویژه در پوشه پیوست و نام فایل که باید جایگزین یا حذف شوند.\nبرای حفظ کراکترهای ویژه خالی بگذارید.',
      name: 'کراکترهای ویژه'
    },
    specialCharactersReplacement: {
      description: 'رشته جایگزین برای کراکترهای ویژه در پوشه پیوست و نام فایل.\nبرای حذف کراکترهای ویژه خالی بگذارید.',
      name: 'جایگزین کراکترهای ویژه'
    },
    timeoutInSeconds: {
      description: 'زمان انقضا به ثانیه برای همه عملیات.\nاگر {{zero}} تنظیم شود، زمان انقضای اجرای عملیات غیرفعال می‌شود.',
      name: 'زمان انقضا به ثانیه'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'تغییر نام فایل پیوست',
    folderTitle: 'انتخاب پوشه پیوست',
    previewModal: {
      title: 'پیش‌نمایش فایل پیوست \'{{fullFileName}}\''
    },
    title: 'مقداری برای نشان درخواست ارائه دهید'
  },
  regularExpression: '/عبارت قانونی/'
};
