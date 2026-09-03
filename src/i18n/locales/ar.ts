export const ar = {
  attachmentCollector: {
    confirm: {
      part1: 'هل تريد جمع المرفقات لكل الملاحظات داخل المجلدات بشكلٍ متكرر؟',
      part2: 'لا يمكن التراجع عن هذه العملية.'
    },
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
    content: {
      part1: 'المرفق',
      part2: 'يتم الرجوع إليه من عدة ملاحظات.'
    },
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
  menuItems: {
    collectAttachmentsInFile: 'جمع المرفقات في الملف',
    collectAttachmentsInFiles: 'جمع المرفقات في الملفات'
  },
  notice: {
    collectingAttachments: 'جمع المرفقات لـ \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'تم إلغاء جمع المرفقات. راجع وحدة التحكم للتفاصيل.',
    generatedAttachmentFileNameIsInvalid: {
      part1: 'اسم ملف المرفق المُولد \'{{path}}\' غير صالح.\n{{validationMessage}}\nتحقق من',
      part2: 'الإعداد.'
    },
    notePathIsIgnored: 'مسار الملاحظة مُتجاهل'
  },
  obsidianDevUtils: {
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
      codeComment: '// تم تعليق الرموز المخصصة لأنها تحتاج إلى تحديث للتنسيق الجديد المُقدم في إصدار الإضافة 9.0.0.\n// راجع الوثائق (https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#custom-tokens) لمزيد من المعلومات.',
      deprecated: {
        part1: 'في إصدار الإضافة 9.0.0، تغير تنسيق تسجيل الرمز المخصص. يرجى تحديث رموزك وفقاً لذلك. راجع',
        part2: 'الوثائق',
        part3: 'لمزيد من المعلومات'
      }
    },
    legacyRenameAttachmentsToLowerCase: {
      part1: 'في إصدار الإضافة 9.0.0،',
      part2: 'الإعداد مُهمل. استخدم',
      part3: 'التنسيق بدلاً من ذلك. انظر',
      part4: 'الوثائق',
      part5: 'لمزيد من المعلومات'
    },
    markdownUrlFormat: {
      deprecated: {
        part1: 'لديك قيمة محتملة غير صحيحة مُعينة لـ',
        part2: 'التنسيق. يرجى الرجوع إلى',
        part3: 'الوثائق',
        part4: 'لمزيد من المعلومات',
        part5: 'لن تظهر هذه الرسالة مرة أخرى.'
      }
    },
    specialCharacters: {
      part1: 'في إصدار الإضافة 9.16.0،',
      part2: 'تم تغيير قيمة الإعداد الافتراضية. تم تحديث قيمة إعدادك إلى القيمة الافتراضية الجديدة.'
    },
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
      description: {
        part1: 'عند إرفاق الملفات:'
      },
      name: 'وضع إعادة تسمية المرفقات'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: {
        part1: 'عندما يتم استخدام المرفق المجموع من عدة ملاحظات:'
      },
      name: 'وضع جمع المرفق المستخدم من عدة ملاحظات'
    },
    collectedAttachmentFileName: {
      description: {
        part1: 'انظر',
        part2: 'الرموز المتاحة',
        part3: 'اتركه فارغاً للاحتفاظ باسم ملف المرفق الأصلي.'
      },
      name: 'اسم ملف المرفق المجموع'
    },
    customTokens: {
      description: {
        part1: 'الرموز المخصصة المراد استخدامها.',
        part2: 'انظر',
        part3: 'الوثائق',
        part4: 'لمزيد من المعلومات.',
        part5: '⚠️ يمكن أن تكون الرموز المخصصة كود JavaScript عشوائي. إذا كانت مكتوبة بشكل سيء، يمكن أن تسبب فقدان البيانات. استخدمها على مسؤوليتك الخاصة.'
      },
      name: 'الرموز المخصصة'
    },
    defaultImageSize: {
      description: {
        part1: 'الحجم الافتراضي للصورة.',
        part2: 'يمكن تحديده بالبكسل',
        part3: 'أو كنسبة مئوية من الحجم الكامل للصورة',
        part4: 'اتركه فارغًا لاستخدام الحجم الأصلي.'
      },
      name: 'الحجم الافتراضي للصورة'
    },
    duplicateNameSeparator: {
      description: {
        part1: 'عندما تقوم بلصق/سحب ملف بنفس اسم ملف موجود، سيتم إضافة هذا الفاصل إلى اسم الملف.',
        part2: 'مثلاً، عندما تسحب الملف',
        part3: '، سيتم إعادة تسميته إلى',
        part4: '، إلخ، للحصول على أول اسم متاح.'
      },
      name: 'فاصل الأسماء المكررة'
    },
    excludePathsFromAttachmentCollecting: {
      description: {
        part1: 'استبعاد المرفقات من المسارات التالية عند',
        part2: 'جمع المرفقات',
        part3: 'تنفيذ الأمر.',
        part4: 'أدخل كل مسار في سطر جديد.',
        part5: 'يمكنك استخدام سلسلة المسار أو',
        part6: 'إذا كان الإعداد فارغاً، لن يتم استبعاد أي مسارات من جمع المرفقات.'
      },
      name: 'استبعاد المسارات من جمع المرفقات'
    },
    generatedAttachmentFileName: {
      description: {
        part1: 'انظر',
        part2: 'الرموز المتاحة'
      },
      name: 'اسم ملف المرفق المُولد'
    },
    jpegQuality: {
      description: 'كلما قل الجودة، زادت نسبة الضغط.',
      name: 'جودة JPEG'
    },
    locationForNewAttachments: {
      description: {
        part1: 'ابدأ بـ',
        part2: 'لاستخدام المسار النسبي.',
        part3: 'انظر',
        part4: 'الرموز المتاحة',
        part5: 'المجلدات النقطية مثل',
        part6: 'غير موصى بها، لأن Obsidian لا يتتبعها. قد تحتاج إلى استخدام',
        part7: 'إضافة لإدارتها.'
      },
      name: 'موقع المرفقات الجديدة'
    },
    markdownUrlFormat: {
      description: {
        part1: 'تنسيق الرابط الذي سيتم إدراجه في Markdown.',
        part2: 'انظر',
        part3: 'الرموز المتاحة',
        part4: 'اتركه فارغاً لاستخدام التنسيق الافتراضي.'
      },
      name: 'تنسيق رابط Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: {
        part1: 'ما إذا كان سيتم تطبيق إعدادات مجلد المرفقات واسم الملف على المرفقات التي تنشئها إضافات أخرى.',
        part2: 'تكتب بعض الإضافات المرفق مباشرة في الخزنة باسم من اختيارها، دون سؤال Obsidian عن مكانه الصحيح. عند تفعيل هذا الخيار، يتم نقل هذا الملف وإعادة تسميته فور ظهوره.',
        part3: 'تتم معالجة الملفات التي تُنشأ أثناء فتح ملاحظة فقط، ولا تُمس أبدًا الملفات القادمة من المزامنة أو من استيراد خزنة.'
      },
      name: 'إعادة تسمية المرفقات التي تنشئها الإضافات الأخرى'
    },
    renameAttachmentsToLowerCase: 'إعادة تسمية المرفقات بأحرف صغيرة',
    renamedAttachmentFileName: {
      description: {
        part1: 'انظر',
        part2: 'الرموز المتاحة',
        part3: 'اتركه فارغاً للاحتفاظ باسم ملف المرفق الأصلي.'
      },
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
      description: {
        part1: 'إذا تم تفعيله، المرفقات المعالجة عبر',
        part2: 'جمع المرفقات',
        part3: 'الأوامر سيتم إعادة تسميتها وفقاً لـ',
        part4: 'الإعداد.'
      },
      name: 'يجب إعادة تسمية المرفقات المجموعة'
    },
    specialCharacters: {
      description: {
        part1: 'الأحرف الخاصة في مجلد المرفقات واسم الملف المراد استبدالها أو إزالتها.',
        part2: 'اتركه فارغاً للحفاظ على الأحرف الخاصة.'
      },
      name: 'الأحرف الخاصة'
    },
    specialCharactersReplacement: {
      description: {
        part1: 'سلسلة الاستبدال للأحرف الخاصة في مجلد المرفقات واسم الملف.',
        part2: 'اتركه فارغاً لإزالة الأحرف الخاصة.'
      },
      name: 'استبدال الأحرف الخاصة'
    },
    timeoutInSeconds: {
      description: {
        part1: 'مهلة الوقت بالثواني لجميع العمليات.',
        part2: 'إذا تم تعيين',
        part3: '، يتم تعطيل مهلة تنفيذ العمليات.'
      },
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
