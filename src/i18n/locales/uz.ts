export const uz = {
  attachmentCollector: {
    confirm: 'Papkalardagi barcha eslatmalar uchun qo\'shimchalarni ichki papkalar bilan birga yig\'ishni xohlaysizmi?\n{{folders}}\nBu amalni ortga qaytarib bo\'lmaydi.',
    progressBar: {
      message: 'Qo\'shimchalarni yig\'layapman {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Qo\'shimchalarni yig\'layapman...'
    }
  },
  buttons: {
    copy: 'Nusxalash',
    move: 'Ko\'chirish',
    previewAttachmentFile: 'Qo\'shimcha faylni oldindan ko\'rish',
    skip: 'O\'tkazib yuborish'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: '{{attachment}} qo\'shimchasiga bir nechta eslatmalar havola qilgan.',
    heading: 'Bir nechta eslatmalar tomonidan ishlatiladigan qo\'shimchani yig\'moqdaman',
    noPriorityWinnerReason: {
      EmptyList: '{{settingName}} sozlamasi boʻsh boʻlgani uchun koʻchirilmadi, shu sababli bu eslatmalardan qaysi biri unga egalik qilishini hech narsa hal qilmaydi.',
      NoMatch: 'Bu eslatmalarning hech biri {{settingName}} sozlamasidagi biror yozuvga mos kelmagani uchun koʻchirilmadi.',
      Tie: 'Bu eslatmalarning bir nechtasi {{settingName}} sozlamasiga bir xilda mos kelgani uchun yagona egasi aniqlanmadi va u koʻchirilmadi.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Boshqa muammoli qo\'shimchalar uchun bir xil harakatni ishlatish kerak'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Joriy papkadagi qo\'shimchalarni yig\'lash',
    collectAttachmentsCurrentNote: 'Joriy eslatmadagi qo\'shimchalarni yig\'lash',
    collectAttachmentsEntireVault: 'Butun ombordagi qo\'shimchalarni yig\'lash'
  },
  links: {
    documentation: 'hujjatlarga',
    tokens: 'tokenlarni'
  },
  menuItems: {
    collectAttachmentsInFile: 'Faylda ilovalarni to‘plash',
    collectAttachmentsInFiles: 'Fayllarda ilovalarni to‘plash'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: '\'{{noteFilePath}}\' uchun qo\'shimchalarni yig\'layapman',
    collectingAttachmentsCancelled: 'Qo\'shimchalarni yig\'lash bekor qilindi. Tafsilotlar uchun konsolni ko\'ring.',
    generatedAttachmentFileNameIsInvalid: 'Yaratilgan qo\'shimcha fayl nomi \'{{path}}\' noto\'g\'ri.\n{{validationMessage}}\n{{settingName}} sozlamangizni tekshiring.',
    notePathIsIgnored: 'Eslatma yo\'li e\'tiborga olinmaydi'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Bekor qilish',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Sahifaga elementlar:',
      jumpToPage: 'Sahifaga o\'tish:'
    },
    notices: {
      attachmentIsStillUsed: 'Qo\'shimcha {{attachmentPath}} hali ham boshqa eslatmalar tomonidan ishlatilmoqda. U o\'chirilmaydi.',
      unhandledError: 'Qayta ishlanmagan xatolik yuz berdi. Iltimos, qo\'shimcha ma\'lumot uchun konsolni tekshiring.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'Barcha fayllar qayta nomlanadi.',
        displayText: 'Barchasi'
      },
      none: {
        description: 'Ularning nomlari saqlanadi.',
        displayText: 'Hech biri'
      },
      onlyPastedImages: {
        description: 'Faqat yopishtirilgan rasmlar qayta nomlanadi. Faqqt PNG rasm kontenti bevosita buferdan yopishtirilganida amal qiladi. Odatda skrinshotlar uchun.',
        displayText: 'Faqat yopishtirilgan rasmlar'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'Qo\'shimchalarni yig\'lashni bekor qilish.',
        displayText: 'Bekor qilish'
      },
      copy: {
        description: 'Qo\'shimchani yangi joyga nusxalash.',
        displayText: 'Nusxalash'
      },
      move: {
        description: 'Qo\'shimchani yangi joyga ko\'chirish.',
        displayText: 'Ko\'chirish'
      },
      prompt: {
        description: 'Foydalanuvchidan amal tanlashni so\'rash.',
        displayText: 'So\'rash'
      },
      skip: {
        description: 'Qo\'shimchani o\'tkazib yuborish va keyingisiga o\'tish.',
        displayText: 'O\'tkazib yuborish'
      }
    },
    defaultImageSizeDimension: {
      height: 'Balandlik',
      width: 'Kenglik'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Maxsus tokenlar komment qilindi, chunki ular 9.0.0 versiyasidagi yangi format bo\'yicha yangilanishi kerak.\n// Qo\'shimcha ma\'lumot uchun hujjatlarga ({{customTokensDocumentationUrl}}) murojaat qiling.',
      deprecated: 'Maxsus tokenlarni ro\'yxatga olish formati o\'zgardi. Iltimos, tokenlaringizni shunga mos ravishda yangilang. Batafsil ma\'lumot uchun {{documentation}} murojaat qiling.'
    },
    legacyRenameAttachmentsToLowerCase: '{{setting}} sozlamasi eskirgan. Buning o\'rniga {{format}} formatidan foydalaning. Batafsil ma\'lumot uchun {{documentation}} qarang.',
    markdownUrlFormat: {
      deprecated: '{{setting}} formati uchun noto\'g\'ri bo\'lishi mumkin bo\'lgan qiymat o\'rnatilgan. Batafsil ma\'lumot uchun {{documentation}} murojaat qiling. Bu xabar boshqa ko\'rsatilmaydi.'
    },
    specialCharacters: '{{setting}} sozlamasining standart qiymati o\'zgardi. Sozlamangiz qiymati yangi standart qiymatga yangilandi.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Standart rasm o‘lchami piksel yoki foizda bo‘lishi kerak',
      invalidCustomTokensCode: 'Noto\'g\'ri maxsus token kodi',
      invalidRegularExpression: 'Noto\'g\'ri tartibiy ifoda {{regExp}}',
      specialCharactersMustNotContainSlash: 'Maxsus belgilar / ni o\'z ichiga olmang',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Maxsus belgi o\'rnini bosuvchi fayl nomi yoki yo\'l belgilari bo\'lmasligi kerak.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Fayllar qo\'shilganda:',
      name: 'Qo\'shimchalarni qayta nomlash rejimi'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Yig\'ilgan qo\'shimcha bir nechta eslatmalarda ishlatilganda:',
      name: 'Bir nechta eslatmalar tomonidan foydalanilgan qo\'shimchani yig\'ish rejimi'
    },
    collectedAttachmentFileName: {
      description: 'Mavjud {{tokens}} ko\'ring.\nQo\'shimchaning joriy fayl nomini saqlash uchun bo\'sh qoldiring.',
      name: 'Yig\'ilgan qo\'shimcha fayl nomi'
    },
    customTokens: {
      description: 'Foydalaniladigan maxsus tokenlar.\nBatafsil ma\'lumot uchun {{documentation}} qarang.\n⚠️ Maxsus tokenlar istalgan JavaScript kodi bo\'lishi mumkin. Yomon yozilgan bo\'lsa, ma\'lumotlar yo\'qolishiga olib kelishi mumkin. O\'z xavfingiz ostida foydalaning.',
      name: 'Maxsus tokenlar'
    },
    defaultImageSize: {
      description: 'Standart rasm o‘lchami.\nPikselda ({{pixels}}) yoki rasm to‘liq o‘lchamining foizida ({{percentage}}) ko‘rsatilishi mumkin.\nAsl rasm o‘lchamidan foydalanish uchun bo‘sh qoldiring.',
      name: 'Standart rasm o‘lchami'
    },
    duplicateNameSeparator: {
      description: 'Mavjud fayl bilan bir xil nomdagi faylni joylashtirganingizda yoki sudrab olib kirganingizda, ushbu ajratgich fayl nomiga qo\'shiladi.\nMasalan, {{existingFile}} faylini sudrab olib kirganingizda, u birinchi bo\'sh nom tanlanib, {{firstAvailableName}}, {{secondAvailableName}} va hokazo deb qayta nomlanadi.',
      name: 'Nusxa nom ajratgichi'
    },
    excludePathsFromAttachmentCollecting: {
      description: '{{command}} buyrug\'i bajarilganda quyidagi yo\'llardagi qo\'shimchalar chiqarib tashlanadi.\nHar bir yo\'lni yangi qatorda yozing.\n{{pathSyntax}}\nSozlama bo\'sh bo\'lsa, qo\'shimchalarni yig\'ishdan hech qanday yo\'l chiqarib tashlanmaydi.',
      name: 'Qo\'shimcha yig\'ishda chiqarib tashlangan yo\'llar'
    },
    generatedAttachmentFileName: {
      description: 'Mavjud {{tokens}} ko\'ring.',
      name: 'Yaratilgan qo\'shimcha fayl nomi'
    },
    jpegQuality: {
      description: 'Sifat qanchalik past bo\'lsa, siqish darajasi shunchalik yuqori bo\'ladi.',
      name: 'JPEG sifati'
    },
    locationForNewAttachments: {
      description: 'Eslatmaning ota papkasiga nisbatan yo\'llar uchun {{relativePrefix}} bilan boshlang.\nMavjud {{tokens}} ko\'ring.\n{{dotFolder}} kabi nuqta bilan boshlanadigan papkalar tavsiya etilmaydi, chunki Obsidian ularni kuzatmaydi. Ularni boshqarish uchun {{unhidePlugin}} plaginidan foydalanishingiz kerak bo\'lishi mumkin.',
      name: 'Yangi qo\'shimchalar joylashuvi'
    },
    markdownUrlFormat: {
      description: 'Qo\'shimcha qo\'shilganda Markdown-ga qo\'yiladigan URL formati. U faqat shu paytda qo\'llaniladi: eslatma yoki qo\'shimcha qayta nomlanganda yoki ko\'chirilganda Obsidian keyinroq qayta yozadigan havola standart formatni oladi.\nMavjud {{tokens}} ko\'ring.\nStandart formatdan foydalanish uchun bo\'sh qoldiring.',
      name: 'Markdown URL formati'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Ilova papkasi va fayl nomi sozlamalari BOSHQA plaginlar yaratgan ilovalarga ham qo\'llanilsinmi.\nBa\'zi plaginlar ilovani qayerga tegishli ekanini Obsidian\'dan so\'ramasdan, o\'z nomi bilan to\'g\'ridan-to\'g\'ri omborga yozadi. Bu yoqilganda, bunday fayl paydo bo\'lishi bilanoq ko\'chiriladi va nomi o\'zgartiriladi.\nFaqat eslatma ochiq turganda yaratilgan va eslatmadan havola qilingan fayllarga tegiladi: hech bir eslatma havola qilmagan fayl boshqa plagin o\'zi uchun saqlaydigan ma\'lumotdir va yozilgan joyida qoladi. Sinxronlash yoki ombor importidan kelgan fayllarga hech qachon tegilmaydi.\n{{modes}}\nFaylni yaratgan plagin yozish amalining chaqiruvlar stekidan aniqlanadi. Bu imkon qadar amalga oshiriladi: Obsidian\'ning o\'zi, sinxronlash mijozi yoki yozishni keyinga qoldiradigan plagin yozgan fayl uchun hech qanday plagin aniqlanmaydi. Bunday fayl quyidagi ro\'yxatda YO\'Q deb hisoblanadi.',
      name: 'Boshqa plaginlar yaratgan ilovalar nomini o\'zgartirish'
    },
    renameAttachmentsToLowerCase: 'Qo\'shimchilarning nomlarini kichik harflarga o\'zgartirish',
    renamedAttachmentFileName: {
      description: 'Mavjud {{tokens}} ko\'ring.\nQo\'shimchaning joriy fayl nomini saqlash uchun bo\'sh qoldiring.',
      name: 'Qayta nomlangan qo\'shimcha fayl nomi'
    },
    resetToSampleCustomTokens: {
      message: 'Maxsus tokenlarni namuna tokenlarga qaytarishni xohlaysizmi? O\'zgartirishlaringiz yo\'qoladi.',
      title: 'Namuna tokenlarga qaytarish'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Yopishtirilgan rasmlarni JPEG formatiga aylantirish-aylantirilmasligini belgilaydi. Bu faqat PNG rasmlar bo\'lsa va to\'g\'ridan-to\'g\'ri panodan yopishtirilganda ishlatiladi. Odatda, skrinshotlar uchun.',
      name: 'Yopishtirilgan rasmlarni JPEG-ga o\'zgartirish'
    },
    shouldRenameCollectedAttachments: {
      description: 'Yoqilgan bo\'lsa, {{command}} buyruqlari orqali qayta ishlangan qo\'shimchalar {{setting}} sozlamasiga muvofiq qayta nomlanadi.',
      name: 'Yig\'ilgan qo\'shimchalarni qayta nomlash'
    },
    specialCharacters: {
      description: 'Qo\'shimcha papkasi va fayl nomidagi almashtiriladigan yoki olib tashlanadigan maxsus belgilar.\nMaxsus belgilarni saqlash uchun bo\'sh qoldiring.',
      name: 'Maxsus belgilar'
    },
    specialCharactersReplacement: {
      description: 'Qo\'shimcha papkasi va fayl nomidagi maxsus belgilar o\'rniga qo\'yiladigan satr.\nMaxsus belgilarni olib tashlash uchun bo\'sh qoldiring.',
      name: 'Maxsus belgilarni almashtirish'
    },
    timeoutInSeconds: {
      description: 'Barcha amallar uchun vaqt cheklovi (soniyalarda).\nAgar {{zero}} belgilansa, amallarni bajarish vaqti cheklovi o\'chiriladi.',
      name: 'Vaqt tugashi (soniya)'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Ilova faylini qayta nomlash',
    folderTitle: 'Ilova papkasini tanlang',
    previewModal: {
      title: 'Qo\'shimcha faylni oldindan ko\'rish \'{{fullFileName}}\''
    },
    title: 'So\'rov tokeni uchun qiymat kiriting'
  },
  regularExpression: '/muntazam ifoda/'
};
