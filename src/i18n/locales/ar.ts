export const ar = {
  attachmentCollector: {
    confirm: 'هل تريد جمع المرفقات لكل الملاحظات داخل المجلدات بشكلٍ متكرر؟\n{{folders}}\nلا يمكن التراجع عن هذه العملية.',
    progressBar: {
      message: 'جمع المرفقات {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'جمع المرفقات...'
    }
  },
  buttons: {
    copy: 'نسخ',
    move: 'نقل',
    previewAttachmentFile: 'معاينة ملف المرفق',
    skip: 'تخطي'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'المرفق {{attachment}} مُشار إليه من عدة ملاحظات.',
    heading: 'جمع المرفق المستخدم من عدة ملاحظات',
    noPriorityWinnerReason: {
      EmptyList: 'لم يتم نقله لأن إعداد {{settingName}} فارغ، لذا لا شيء يحدد أي من هذه الملاحظات يملكه.',
      NoMatch: 'لم يتم نقله لأن أياً من هذه الملاحظات لا يطابق أي إدخال في إعداد {{settingName}}.',
      Tie: 'لم يتم نقله لأن عدة ملاحظات من هذه تطابق إعداد {{settingName}} بالقدر نفسه، لذا فهو لا يحدد مالكاً واحداً.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'يجب استخدام نفس الإجراء للمرفقات المشكوك فيها الأخرى'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'جمع المرفقات في المجلد الحالي',
    collectAttachmentsCurrentNote: 'جمع المرفقات في الملاحظة الحالية',
    collectAttachmentsEntireVault: 'جمع المرفقات في الخزانة بأكملها'
  },
  links: {
    documentation: 'الوثائق',
    tokens: 'الرموز'
  },
  menuItems: {
    collectAttachmentsInFile: 'جمع المرفقات في الملف',
    collectAttachmentsInFiles: 'جمع المرفقات في الملفات'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'جمع المرفقات لـ \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'تم إلغاء جمع المرفقات. راجع وحدة التحكم للتفاصيل.',
    generatedAttachmentFileNameIsInvalid: 'اسم ملف المرفق المُولد \'{{path}}\' غير صالح.\n{{validationMessage}}\nتحقق من إعداد {{settingName}}.',
    notePathIsIgnored: 'مسار الملاحظة مُتجاهل'
  },
  obsidianLib: {
    buttons: {
      cancel: 'إلغاء',
      ok: 'موافق'
    },
    dataview: {
      itemsPerPage: 'العناصر في الصفحة:',
      jumpToPage: 'الانتقال إلى الصفحة:'
    },
    notices: {
      attachmentIsStillUsed: 'المرفق {{attachmentPath}} لا يزال مستخدماً من ملاحظات أخرى. لن يتم حذفه.',
      unhandledError: 'حدث خطأ غير معالج. يرجى التحقق من وحدة التحكم لمزيد من المعلومات.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'جميع الملفات يتم إعادة تسميتها.',
        displayText: 'الكل'
      },
      none: {
        description: 'أسماؤها محفوظة.',
        displayText: 'لا شيء'
      },
      onlyPastedImages: {
        description: 'الصور المُلصقة فقط يتم إعادة تسميتها. ينطبق فقط عند لصق محتوى صورة PNG مباشرة من الحافظة. عادة، للصق لقطات الشاشة.',
        displayText: 'الصور المُلصقة فقط'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'إلغاء جمع المرفقات.',
        displayText: 'إلغاء'
      },
      copy: {
        description: 'نسخ المرفق إلى الموقع الجديد.',
        displayText: 'نسخ'
      },
      move: {
        description: 'نقل المرفق إلى الموقع الجديد.',
        displayText: 'نقل'
      },
      prompt: {
        description: 'مطالبة المستخدم باختيار الإجراء.',
        displayText: 'مطالبة'
      },
      skip: {
        description: 'تخطي المرفق والمتابعة إلى التالي.',
        displayText: 'تخطي'
      }
    },
    defaultImageSizeDimension: {
      height: 'الارتفاع',
      width: 'العرض'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// تم تعليق الرموز المخصصة لأنها تحتاج إلى تحديث للتنسيق الجديد المُقدم في إصدار الإضافة 9.0.0.\n// راجع الوثائق ({{customTokensDocumentationUrl}}) لمزيد من المعلومات.',
      deprecated: 'تغيّر تنسيق تسجيل الرموز المخصصة. يرجى تحديث رموزك وفقاً لذلك. راجع {{documentation}} لمزيد من المعلومات.'
    },
    legacyRenameAttachmentsToLowerCase: 'إعداد {{setting}} مُهمل. استخدم تنسيق {{format}} بدلاً منه. انظر {{documentation}} لمزيد من المعلومات.',
    markdownUrlFormat: {
      deprecated: 'ربما عيّنت قيمة غير صحيحة لتنسيق {{setting}}. يرجى الرجوع إلى {{documentation}} لمزيد من المعلومات. لن تظهر هذه الرسالة مرة أخرى.'
    },
    specialCharacters: 'تغيّرت القيمة الافتراضية لإعداد {{setting}}. تم تحديث قيمة إعدادك إلى القيمة الافتراضية الجديدة.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'يجب أن يكون حجم الصورة الافتراضي بالبكسل أو بالنسبة المئوية',
      invalidCustomTokensCode: 'كود الرموز المخصصة غير صالح',
      invalidRegularExpression: 'التعبير النمطي غير صالح {{regExp}}',
      specialCharactersMustNotContainSlash: 'الأحرف الخاصة يجب ألا تحتوي على /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'استبدال الأحرف الخاصة يجب ألا يحتوي على أحرف مسار اسم ملف غير صالحة.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'عند إرفاق الملفات:',
      name: 'وضع إعادة تسمية المرفقات'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'عندما يكون المرفق المجموع مستخدماً من عدة ملاحظات:',
      name: 'وضع جمع المرفق المستخدم من عدة ملاحظات'
    },
    collectedAttachmentFileName: {
      description: 'انظر {{tokens}} المتاحة.\nاتركه فارغاً للاحتفاظ بالاسم الحالي لملف المرفق.',
      name: 'اسم ملف المرفق المجموع'
    },
    customTokens: {
      description: 'الرموز المخصصة المراد استخدامها.\nانظر {{documentation}} لمزيد من المعلومات.\n⚠️ يمكن أن تكون الرموز المخصصة كود JavaScript عشوائياً. إذا كُتبت بشكل سيئ، فقد تتسبب في فقدان البيانات. استخدمها على مسؤوليتك الخاصة.',
      name: 'الرموز المخصصة'
    },
    defaultImageSize: {
      description: 'الحجم الافتراضي للصورة.\nيمكن تحديده بالبكسل ({{pixels}}) أو كنسبة مئوية من الحجم الكامل للصورة ({{percentage}}).\nاتركه فارغاً لاستخدام الحجم الأصلي للصورة.',
      name: 'الحجم الافتراضي للصورة'
    },
    duplicateNameSeparator: {
      description: 'عندما تلصق/تسحب ملفاً بنفس اسم ملف موجود، سيُضاف هذا الفاصل إلى اسم الملف.\nمثلاً، عندما تسحب الملف {{existingFile}}، ستتم إعادة تسميته إلى {{firstAvailableName}}، {{secondAvailableName}}، إلخ، باستخدام أول اسم متاح.',
      name: 'فاصل الأسماء المكررة'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'استبعاد المرفقات من المسارات التالية عند تنفيذ الأمر {{command}}.\nأدخل كل مسار في سطر جديد.\n{{pathSyntax}}\nإذا كان الإعداد فارغاً، فلن يُستبعد أي مسار من جمع المرفقات.',
      name: 'استبعاد المسارات من جمع المرفقات'
    },
    generatedAttachmentFileName: {
      description: 'انظر {{tokens}} المتاحة.',
      name: 'اسم ملف المرفق المُولد'
    },
    jpegQuality: {
      description: 'كلما قل الجودة، زادت نسبة الضغط.',
      name: 'جودة JPEG'
    },
    locationForNewAttachments: {
      description: 'ابدأ بـ {{relativePrefix}} للمسارات النسبية إلى المجلد الأب للملاحظة.\nانظر {{tokens}} المتاحة.\nالمجلدات النقطية مثل {{dotFolder}} غير موصى بها، لأن Obsidian لا يتتبعها. قد تحتاج إلى استخدام إضافة {{unhidePlugin}} لإدارتها.',
      name: 'موقع المرفقات الجديدة'
    },
    markdownUrlFormat: {
      description: 'تنسيق الرابط الذي سيتم إدراجه في Markdown عند إضافة مرفق. يُطبَّق في تلك اللحظة فقط: الرابط الذي يعيد Obsidian كتابته لاحقاً، عند إعادة تسمية ملاحظة أو مرفق أو نقلهما، يحصل على التنسيق الافتراضي.\nانظر {{tokens}} المتاحة.\nاتركه فارغاً لاستخدام التنسيق الافتراضي.',
      name: 'تنسيق رابط Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'ما إذا كان سيتم تطبيق إعدادات مجلد المرفقات واسم الملف على المرفقات التي تنشئها إضافات أخرى.\nتكتب بعض الإضافات المرفق مباشرة في الخزنة باسم من اختيارها، دون سؤال Obsidian عن مكانه الصحيح. عند تفعيل هذا الخيار، يتم نقل هذا الملف وإعادة تسميته فور ظهوره.\nلا تتم معالجة إلا الملفات التي تُنشأ أثناء فتح ملاحظة وترتبط بها ملاحظة: الملف الذي لا ترتبط به أي ملاحظة هو بيانات تحتفظ بها إضافة أخرى لنفسها، فيبقى حيث كُتب. ولا تُمس أبدًا الملفات القادمة من المزامنة أو من استيراد خزنة.\n{{modes}}\nتُحدَّد الإضافة المنشئة من مكدس الاستدعاءات لعملية الكتابة. وهذا على أساس أفضل جهد: لا تُحدَّد أي إضافة لملف كتبه Obsidian نفسه، أو عميل مزامنة، أو إضافة تؤجل كتابتها. ويُعامَل مثل هذا الملف على أنه غير موجود في القائمة أدناه.',
      name: 'إعادة تسمية المرفقات التي تنشئها الإضافات الأخرى'
    },
    renameAttachmentsToLowerCase: 'إعادة تسمية المرفقات بأحرف صغيرة',
    renamedAttachmentFileName: {
      description: 'انظر {{tokens}} المتاحة.\nاتركه فارغاً للاحتفاظ بالاسم الحالي لملف المرفق.',
      name: 'اسم ملف المرفق المُعاد تسميته'
    },
    resetToSampleCustomTokens: {
      message: 'هل أنت متأكد من أنك تريد إعادة تعيين الرموز المخصصة إلى الرموز المخصصة النموذجية؟ ستضيع تغييراتك.',
      title: 'إعادة تعيين إلى الرموز المخصصة النموذجية'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'ما إذا كان يجب تحويل الصور المُلصقة إلى JPEG. ينطبق فقط عند لصق محتوى صورة PNG مباشرة من الحافظة. عادة، للصق لقطات الشاشة.',
      name: 'يجب تحويل الصور المُلصقة إلى JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'إذا تم تفعيله، فستتم إعادة تسمية المرفقات المعالجة عبر أوامر {{command}} وفقاً لإعداد {{setting}}.',
      name: 'يجب إعادة تسمية المرفقات المجموعة'
    },
    specialCharacters: {
      description: 'الأحرف الخاصة في مجلد المرفقات واسم الملف المراد استبدالها أو إزالتها.\nاتركه فارغاً للحفاظ على الأحرف الخاصة.',
      name: 'الأحرف الخاصة'
    },
    specialCharactersReplacement: {
      description: 'سلسلة الاستبدال للأحرف الخاصة في مجلد المرفقات واسم الملف.\nاتركه فارغاً لإزالة الأحرف الخاصة.',
      name: 'استبدال الأحرف الخاصة'
    },
    timeoutInSeconds: {
      description: 'مهلة الوقت بالثواني لجميع العمليات.\nإذا تم تعيين {{zero}}، يتم تعطيل مهلة تنفيذ العمليات.',
      name: 'مهلة الوقت بالثواني'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'إعادة تسمية ملف المرفق',
    folderTitle: 'اختر مجلد المرفقات',
    previewModal: {
      title: 'معاينة ملف المرفق \'{{fullFileName}}\''
    },
    title: 'قدم قيمة للرمز المطالبة'
  },
  regularExpression: '/التعبير النمطي/'
};
