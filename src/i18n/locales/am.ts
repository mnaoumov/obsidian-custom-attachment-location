export const am = {
  attachmentCollector: {
    confirm: 'በአቃፊዎች ውስጥ ላሉ ሁሉም ማስታወሻዎች ተያያዥ ፋይሎችን በተደጋጋሚ መሰብሰብ ትፈልጋለህ?\n{{folders}}\nይህ እርምጃ መመለስ አይቻልም።',
    progressBar: {
      message: 'ተያያዥ ፋይሎችን በመሰብሰብ ላይ {{iterationString}} - \'{{noteFilePath}}\'።',
      title: 'ተያያዥ ፋይሎችን በመሰብሰብ ላይ...'
    }
  },
  buttons: {
    copy: 'መቅዳት',
    move: 'መውሰድ',
    previewAttachmentFile: 'ተያያዥ ፋይል ቅድመ እይታ',
    skip: 'መዝለፍ'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'ተያያዥ {{attachment}} በበርካታ ማስታወሻዎች ይጠቀሳል።',
    heading: 'በበርካታ ማስታወሻዎች የሚጠቀም ተያያዥ መሰብሰብ',
    noPriorityWinnerReason: {
      EmptyList: 'የ{{settingName}} ቅንብር ባዶ ስለሆነ አልተዘዋወረም፤ ከእነዚህ ማስታወሻዎች የትኛው እንደሚይዘው የሚወስን ምንም ነገር የለም።',
      NoMatch: 'ከእነዚህ ማስታወሻዎች መካከል አንዳቸውም በ{{settingName}} ቅንብር ውስጥ ካለ ማንኛውም ግቤት ጋር ስለማይዛመዱ አልተዘዋወረም።',
      Tie: 'ከእነዚህ ማስታወሻዎች መካከል በርካቶቹ ከ{{settingName}} ቅንብር ጋር በእኩል ደረጃ ስለሚዛመዱ አንድም ባለቤት ስለማይሰይም አልተዘዋወረም።'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'ለሌሎች ችግር ያላቸው ተያያዦች ተመሳሳይ እርምጃ መጠቀም አለበት'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'በአሁኑ ፎልደር ውስጥ ተያያዦችን መሰብሰብ',
    collectAttachmentsCurrentNote: 'በአሁኑ ማስታወሻ ውስጥ ተያያዦችን መሰብሰብ',
    collectAttachmentsEntireVault: 'በሙሉ ቫውልት ውስጥ ተያያዦችን መሰብሰብ'
  },
  links: {
    documentation: 'ሰነዱን',
    tokens: 'ቶከኖች'
  },
  menuItems: {
    collectAttachmentsInFile: 'በፋይል ውስጥ ተያያዥ ፋይሎችን ሰብስብ',
    collectAttachmentsInFiles: 'በፋይሎች ውስጥ ተያያዥ ፋይሎችን ሰብስብ'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'ለ \'{{noteFilePath}}\' ተያያዦችን በመሰብሰብ ላይ',
    collectingAttachmentsCancelled: 'ተያያዦችን መሰብሰብ ተሰርዟል። ለዝርዝሮች ኮንሶል ይመልከቱ።',
    generatedAttachmentFileNameIsInvalid: 'የተፈጠረው ተያያዥ ፋይል ስም \'{{path}}\' የማይሰራ ነው።\n{{validationMessage}}\nየእርስዎን የ{{settingName}} ቅንብር ይፈትሹ።',
    notePathIsIgnored: 'የማስታወሻ መንገድ ችላ ተብሏል'
  },
  obsidianLib: {
    buttons: {
      cancel: 'መሰረዝ',
      ok: 'እሺ'
    },
    dataview: {
      itemsPerPage: 'በአንድ ገጽ ውስጥ ያሉ ንጥሎች:',
      jumpToPage: 'ወደ ገጽ መዝለፍ:'
    },
    notices: {
      attachmentIsStillUsed: 'ተያያዥ {{attachmentPath}} አሁንም በሌሎች ማስታወሻዎች ይጠቀማል። አይሰረዝም።',
      unhandledError: 'ያልተቆጣጠረ ስህተት ተከስቷል። ለተጨማሪ መረጃ ኮንሶል ይፈትሹ።'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'ሁሉም ፋይሎች ይሰየማሉ።',
        displayText: 'ሁሉም'
      },
      none: {
        description: 'ስሞቻቸው ይጠበቃሉ።',
        displayText: 'ምንም'
      },
      onlyPastedImages: {
        description: 'የተጣበቁ ምስሎች ብቻ ይሰየማሉ። የ PNG ምስል ይዘት ከክሊፕቦርድ በቀጥታ ሲጣበቅ ብቻ ይተገበራል። በተለምዶ፣ ስክሪንሾችን ለመጣበቅ።',
        displayText: 'የተጣበቁ ምስሎች ብቻ'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'ተያያዥ መሰብሰብ መሰረዝ።',
        displayText: 'መሰረዝ'
      },
      copy: {
        description: 'ተያያዥን ወደ አዲሱ ቦታ መቅዳት።',
        displayText: 'መቅዳት'
      },
      move: {
        description: 'ተያያዥን ወደ አዲሱ ቦታ መውሰድ።',
        displayText: 'መውሰድ'
      },
      prompt: {
        description: 'ተጠቃሚውን እርምጃ እንዲመርጥ ማስጠንቀቅ።',
        displayText: 'ማስጠንቀቅ'
      },
      skip: {
        description: 'ተያያዥን መዝለፍ እና ወደ ቀጣዩ መቀጠል።',
        displayText: 'መዝለፍ'
      }
    },
    defaultImageSizeDimension: {
      height: 'እርዝመት',
      width: 'ስፋት'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// የተለመዱ ቶከኖች በፕላጊን ሥሪት 9.0.0 ውስጥ የተዋወቀውን አዲስ ቅርጸት ማዘመን ስለሚያስፈልጋቸው ተሰይመዋል።\n// ለተጨማሪ መረጃ ሰነዱን ይመልከቱ ({{customTokensDocumentationUrl}})።',
      deprecated: 'የተለመዱ ቶከኖች የምዝገባ ቅርጸት ተለውጧል። እባክዎ ቶከኖችዎን በዚሁ መሰረት ያዘምኑ። ለተጨማሪ መረጃ {{documentation}} ይመልከቱ።'
    },
    legacyRenameAttachmentsToLowerCase: 'የ{{setting}} ቅንብር ተቋርጧል። በምትኩ የ{{format}} ቅርጸትን ይጠቀሙ። ለተጨማሪ መረጃ {{documentation}} ይመልከቱ።',
    markdownUrlFormat: {
      deprecated: 'ለ{{setting}} ቅርጸት ምናልባት የተሳሳተ እሴት አስቀምጠው ሊሆን ይችላል። ለተጨማሪ መረጃ እባክዎ {{documentation}} ይመልከቱ። ይህ መልዕክት እንደገና አይታይም።'
    },
    specialCharacters: 'የ{{setting}} ነባሪ ቅንብር እሴት ተለውጧል። የእርስዎ ቅንብር እሴት ወደ አዲሱ ነባሪ እሴት ተዘምኗል።',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'ነባሪ የምስል መጠን በፒክስል ወይም በመቶኛ መሆን አለበት',
      invalidCustomTokensCode: 'የማይሰራ የተለመዱ ቶከኖች ኮድ',
      invalidRegularExpression: 'የማይሰራ መደበኛ አገላለጽ {{regExp}}',
      specialCharactersMustNotContainSlash: 'ልዩ ቁምፊዎች / መያዝ የለባቸውም',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'ልዩ ቁምፊ መተካት የማይሰራ የፋይል ስም መንገድ ቁምፊዎች መያዝ የለባቸውም።'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'ፋይሎች ሲያያይዙ:',
      name: 'ተያያዥ ስም መለወጫ ሁነታ'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'የተሰበሰበው ተያያዥ በበርካታ ማስታወሻዎች ሲጠቀም:',
      name: 'በበርካታ ማስታወሻዎች የሚጠቀም ተያያዥ መሰብሰብ ሁነታ'
    },
    collectedAttachmentFileName: {
      description: 'የሚገኙትን {{tokens}} ይመልከቱ።\nየአሁኑን ተያያዥ ፋይል ስም ለማቆየት ባዶ ይተዉ።',
      name: 'የተሰበሰበ ተያያዥ ፋይል ስም'
    },
    customTokens: {
      description: 'የሚጠቀሙ የተለመዱ ቶከኖች።\nለተጨማሪ መረጃ {{documentation}} ይመልከቱ።\n⚠️ የተለመዱ ቶከኖች የዘፈቀደ JavaScript ኮድ ሊሆኑ ይችላሉ። በመጥፎ ሁኔታ ከተጻፉ፣ የመረጃ ኪሳራ ሊያስከትሉ ይችላሉ። በራስዎ አደጋ ይጠቀሙት።',
      name: 'የተለመዱ ቶከኖች'
    },
    defaultImageSize: {
      description: 'ነባሪ የምስል መጠን።\nበፒክስል ({{pixels}}) ወይም ከሙሉ የምስል መጠን በመቶኛ ({{percentage}}) ሊገለጽ ይችላል።\nኦሪጅናሉን የምስል መጠን ለመጠቀም ባዶ ይተዉ።',
      name: 'ነባሪ የምስል መጠን'
    },
    duplicateNameSeparator: {
      description: 'ከነባር ፋይል ተመሳሳይ ስም ያለው ፋይል ሲጣበቅ/ሲጎተት፣ ይህ መለያያ ወደ ፋይል ስም ይጨመራል።\nለምሳሌ፣ {{existingFile}} የተባለውን ፋይል ሲጎትቱ፣ የመጀመሪያውን የሚገኝ ስም በመያዝ ወደ {{firstAvailableName}}፣ {{secondAvailableName}}፣ ወዘተ ይሰየማል።',
      name: 'የተደጋጋሚ ስም መለያያ'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'የ{{command}} ትዕዛዝ ሲፈጸም ከሚከተሉት መንገዶች ያሉ ተያያዦችን አግልል።\nእያንዳንዱን መንገድ በአዲስ መስመር ያስገቡ።\n{{pathSyntax}}\nቅንብሩ ባዶ ከሆነ፣ ምንም መንገድ ከተያያዥ መሰብሰብ አይገለልም።',
      name: 'ከተያያዥ መሰብሰብ መንገዶችን ማስወገድ'
    },
    generatedAttachmentFileName: {
      description: 'የሚገኙትን {{tokens}} ይመልከቱ።',
      name: 'የተፈጠረ ተያያዥ ፋይል ስም'
    },
    jpegQuality: {
      description: 'ጥራቱ ያነሰ፣ የመጨመቂያ ጥምርታ ይበልጣል።',
      name: 'JPEG ጥራት'
    },
    locationForNewAttachments: {
      description: 'ከማስታወሻው ወላጅ አቃፊ አንጻራዊ ለሆኑ መንገዶች በ{{relativePrefix}} ይጀምሩ።\nየሚገኙትን {{tokens}} ይመልከቱ።\nእንደ {{dotFolder}} ያሉ ዶት-ፎልደሮች አይመከሩም፣ ምክንያቱም Obsidian አይከታተላቸውም። እነሱን ለማስተዳደር የ{{unhidePlugin}} ፕላጊንን መጠቀም ሊያስፈልግዎ ይችላል።',
      name: 'ለአዲስ ተያያዦች ቦታ'
    },
    markdownUrlFormat: {
      description: 'ተያያዥ ሲታከል ወደ Markdown የሚገባው URL ቅርጸት። የሚተገበረው በዚያ ቅጽበት ብቻ ነው፤ ማስታወሻ ወይም ተያያዥ ሲሰየም ወይም ሲንቀሳቀስ Obsidian በኋላ እንደገና የሚጽፈው አገናኝ ነባሪውን ቅርጸት ያገኛል።\nየሚገኙትን {{tokens}} ይመልከቱ።\nነባሪውን ቅርጸት ለመጠቀም ባዶ ይተዉ።',
      name: 'Markdown URL ቅርጸት'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'የተያያዥ አቃፊ እና የፋይል ስም ቅንብሮች ሌሎች ተሰኪዎች በሚፈጥሯቸው ተያያዥ ፋይሎች ላይ ይተግበሩ እንደሆነ።\nአንዳንድ ተሰኪዎች Obsidianን የት እንደሚገባ ሳይጠይቁ ተያያዥ ፋይልን በራሳቸው ስም ወደ ቮልት ይጽፋሉ። ይህ ሲበራ፣ እንዲህ ያለ ፋይል እንደታየ ወዲያውኑ ይንቀሳቀሳል እና ዳግም ይሰየማል።\nማስታወሻ ክፍት ሆኖ የተፈጠሩ እና ከማስታወሻ የተገናኙ ፋይሎች ብቻ ይነካሉ፤ ምንም ማስታወሻ የማያገናኘው ፋይል ሌላ ተሰኪ ለራሱ የሚያቆየው ውሂብ ስለሆነ በተጻፈበት ቦታ ይቆያል። ከማመሳሰል ወይም ከቮልት ማስመጣት የሚመጡ ፋይሎች በጭራሽ አይነኩም።\n{{modes}}\nየፈጠረው ተሰኪ የሚለየው ከጽሑፉ የጥሪ ቁልል ነው። ይህ በተቻለ መጠን ብቻ ነው፤ በObsidian ራሱ፣ በማመሳሰያ ደንበኛ ወይም ጽሑፉን በሚያዘገይ ተሰኪ ለተጻፈ ፋይል ምንም ተሰኪ አይለይም። እንዲህ ያለ ፋይል ከታች ባለው ዝርዝር ውስጥ እንደሌለ ይቆጠራል።',
      name: 'በሌሎች ተሰኪዎች የተፈጠሩ ተያያዥ ፋይሎችን ዳግም ሰይም'
    },
    renameAttachmentsToLowerCase: 'ተያያዦችን ወደ ትንሽ ፊደል መለወጥ',
    renamedAttachmentFileName: {
      description: 'የሚገኙትን {{tokens}} ይመልከቱ።\nየአሁኑን ተያያዥ ፋይል ስም ለማቆየት ባዶ ይተዉ።',
      name: 'የተሰየመ ተያያዥ ፋይል ስም'
    },
    resetToSampleCustomTokens: {
      message: 'የተለመዱ ቶከኖችን ወደ ናሙና የተለመዱ ቶከኖች ማዳከም እርግጠኛ ነዎት? የእርስዎ ለውጦች ይጠፋሉ።',
      title: 'ወደ ናሙና የተለመዱ ቶከኖች መለስ'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'የተጣበቁ ምስሎችን ወደ JPEG መቀየር አለበት እንደሆነ። የ PNG ምስል ይዘት ከክሊፕቦርድ በቀጥታ ሲጣበቅ ብቻ ይተገበራል። በተለምዶ፣ ስክሪንሾችን ለመጣበቅ።',
      name: 'የተጣበቁ ምስሎችን ወደ JPEG መቀየር አለበት'
    },
    shouldRenameCollectedAttachments: {
      description: 'ከነቃ፣ በ{{command}} ትዕዛዞች የሚሰሩ ተያያዦች በ{{setting}} ቅንብር መሰረት ይሰየማሉ።',
      name: 'የተሰበሰቡ ተያያዦችን መሰየም አለበት'
    },
    specialCharacters: {
      description: 'በተያያዥ ፎልደር እና ፋይል ስም ውስጥ የሚተኩ ወይም የሚወገዱ ልዩ ቁምፊዎች።\nልዩ ቁምፊዎችን ለመጠበቅ ባዶ ይተዉ።',
      name: 'ልዩ ቁምፊዎች'
    },
    specialCharactersReplacement: {
      description: 'በተያያዥ ፎልደር እና ፋይል ስም ውስጥ ለልዩ ቁምፊዎች የመተካት ሕብረቁምፊ።\nልዩ ቁምፊዎችን ለማስወገድ ባዶ ይተዉ።',
      name: 'ልዩ ቁምፊዎች መተካት'
    },
    timeoutInSeconds: {
      description: 'ለሁሉም ስራዎች በሰከንድ የሚቆይ ጊዜ።\n{{zero}} ከተዋቀረ፣ የስራዎች አፈጻጸም የጊዜ ገደብ ይሰናከላል።',
      name: 'በሰከንድ የሚቆይ ጊዜ'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'የተያያዥ ፋይል ዳግም ሰይም',
    folderTitle: 'የተያያዥ አቃፊ ይምረጡ',
    previewModal: {
      title: 'ተያያዥ ፋይል ቅድመ እይታ \'{{fullFileName}}\''
    },
    title: 'ለማስጠንቀቂያ ቶከን እሴት ይስጡ'
  },
  regularExpression: '/መደበኛ አገላለጽ/'
};
