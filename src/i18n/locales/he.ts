export const he = {
  attachmentCollector: {
    confirm: 'האם ברצונך לאסוף באופן רקורסיבי קבצים מצורפים לכל הרשימות בתיקיות?\n{{folders}}\nלא ניתן לבטל פעולה זו.',
    progressBar: {
      message: 'אוסף קבצים מצורפים {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'אוסף קבצים מצורפים...'
    }
  },
  buttons: {
    copy: 'העתק',
    move: 'העבר',
    previewAttachmentFile: 'תצוגה מקדימה של קובץ מצורף',
    skip: 'דלג'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'הקובץ המצורף {{attachment}} משומש על ידי מספר רשימות.',
    heading: 'איסוף קובץ מצורף המשומש על ידי מספר רשימות',
    noPriorityWinnerReason: {
      EmptyList: 'הוא לא הועבר משום שההגדרה {{settingName}} ריקה, ולכן דבר אינו קובע לאיזו מהפתקים הללו הוא שייך.',
      NoMatch: 'הוא לא הועבר משום שאף אחד מהפתקים הללו אינו תואם לאף רשומה בהגדרה {{settingName}}.',
      Tie: 'הוא לא הועבר משום שכמה מהפתקים הללו תואמים להגדרה {{settingName}} במידה שווה, ולכן היא אינה קובעת בעלים יחיד.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'יש להשתמש באותה פעולה עבור קבצים מצורפים בעייתיים אחרים'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'אסוף קבצים מצורפים בתיקייה הנוכחית',
    collectAttachmentsCurrentNote: 'אסוף קבצים מצורפים ברשימה הנוכחית',
    collectAttachmentsEntireVault: 'אסוף קבצים מצורפים בכל הכספת'
  },
  links: {
    documentation: 'התיעוד',
    tokens: 'הטוקנים'
  },
  menuItems: {
    collectAttachmentsInFile: 'איסוף קבצים מצורפים בקובץ',
    collectAttachmentsInFiles: 'איסוף קבצים מצורפים בקבצים'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'אוסף קבצים מצורפים עבור \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'איסוף קבצים מצורפים בוטל. ראה קונסול לפרטים.',
    generatedAttachmentFileNameIsInvalid: 'שם הקובץ המצורף שנוצר \'{{path}}\' אינו תקף.\n{{validationMessage}}\nבדוק את ההגדרה {{settingName}}.',
    notePathIsIgnored: 'נתיב רשימה מתעלם'
  },
  obsidianLib: {
    buttons: {
      cancel: 'ביטול',
      ok: 'אישור'
    },
    dataview: {
      itemsPerPage: 'פריטים לעמוד:',
      jumpToPage: 'קפוץ לעמוד:'
    },
    notices: {
      attachmentIsStillUsed: 'קבץ מצורף {{attachmentPath}} עדיין משומש על ידי רשימות אחרות. הוא לא ימחק.',
      unhandledError: 'אירעה שגיאה לא מטופלת. אנא בדוק את הקונסול למידע נוסף.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'כל הקבצים יקבלו שמות חדשים.',
        displayText: 'הכל'
      },
      none: {
        description: 'השמות שלהם נשמרים.',
        displayText: 'כלום'
      },
      onlyPastedImages: {
        description: 'רק תמונות שהודבקו יקבלו שמות חדשים. חל רק כאשר תוכן תמונת PNG מודבק ישירות מהלוח. בדרך כלל, להדבקת צילומי מסך.',
        displayText: 'רק תמונות שהודבקו'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'בטל את איסוף הקבצים המצורפים.',
        displayText: 'ביטול'
      },
      copy: {
        description: 'העתק את הקובץ המצורף למיקום החדש.',
        displayText: 'העתקה'
      },
      move: {
        description: 'העבר את הקובץ המצורף למיקום החדש.',
        displayText: 'העברה'
      },
      prompt: {
        description: 'הנחה את המשתמש לבחור את הפעולה.',
        displayText: 'הנחיה'
      },
      skip: {
        description: 'דלג על הקובץ המצורף והמשך לבא.',
        displayText: 'דילוג'
      }
    },
    defaultImageSizeDimension: {
      height: 'גובה',
      width: 'רוחב'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// טוקנים מותאמים אישיים הועברו להערה מכיוון שהם צריכים להיות מעודכנים לפורמט החדש שהוצג בגרסת תוסף 9.0.0.\n// פנה לתיעוד ({{customTokensDocumentationUrl}}) למידע נוסף.',
      deprecated: 'הפורמט של רישום טוקנים מותאמים אישיים השתנה. אנא עדכן את הטוקנים שלך בהתאם. ראה את {{documentation}} למידע נוסף.'
    },
    legacyRenameAttachmentsToLowerCase: 'ההגדרה {{setting}} מיושנת. השתמש במקומה בפורמט {{format}}. ראה את {{documentation}} למידע נוסף.',
    markdownUrlFormat: {
      deprecated: 'ייתכן שהוגדר אצלך ערך שגוי עבור הפורמט {{setting}}. ראה את {{documentation}} למידע נוסף. הודעה זו לא תוצג שוב.'
    },
    specialCharacters: 'ערך ברירת המחדל של ההגדרה {{setting}} השתנה. ערך ההגדרה שלך עודכן לערך ברירת המחדל החדש.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'גודל התמונה ברירת המחדל חייב להיות בפיקסלים או באחוזים',
      invalidCustomTokensCode: 'קוד טוקנים מותאמים אישיים לא תקף',
      invalidRegularExpression: 'ביטוי רגולרי לא תקף {{regExp}}',
      specialCharactersMustNotContainSlash: 'תווים מיוחדים לא יכולים להכיל /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'החלפת תווים מיוחדים לא יכולה להכיל תווים לא תקפים של נתיב שם קובץ.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'כאשר מצרפים קבצים:',
      name: 'מצב שינוי שם קבצים מצורפים'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'כאשר הקובץ המצורף שנאסף משמש מספר רשימות:',
      name: 'מצב איסוף קובץ מצורף המשמש מספר רשימות'
    },
    collectedAttachmentFileName: {
      description: 'ראה את {{tokens}} הזמינים.\nהשאר ריק כדי לשמור על השם הנוכחי של הקובץ המצורף.',
      name: 'שם קובץ מצורף שנאסף'
    },
    customTokens: {
      description: 'טוקנים מותאמים אישיים לשימוש.\nראה את {{documentation}} למידע נוסף.\n⚠️ טוקנים מותאמים אישיים יכולים להיות קוד JavaScript שרירותי. אם הם כתובים בצורה גרועה, הם עלולים לגרום לאובדן נתונים. השתמש בהם על אחריותך.',
      name: 'טוקנים מותאמים אישיים'
    },
    defaultImageSize: {
      description: 'גודל התמונה ברירת המחדל.\nניתן לציין בפיקסלים ({{pixels}}) או באחוזים מגודל התמונה המלא ({{percentage}}).\nהשאר ריק כדי להשתמש בגודל התמונה המקורי.',
      name: 'גודל התמונה ברירת המחדל'
    },
    duplicateNameSeparator: {
      description: 'כאשר אתה מדביק או גורר קובץ בשם זהה לשם של קובץ קיים, המפריד הזה יתווסף לשם הקובץ.\nלדוגמה, כאשר אתה גורר את הקובץ {{existingFile}}, שמו ישתנה ל-{{firstAvailableName}}, {{secondAvailableName}} וכן הלאה, לפי השם הפנוי הראשון.',
      name: 'מפריד שמות כפולים'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'הדר קבצים מצורפים מהנתיבים הבאים כאשר הפקודה {{command}} מבוצעת.\nהכנס כל נתיב בשורה חדשה.\n{{pathSyntax}}\nאם ההגדרה ריקה, אף נתיב לא מודר מאיסוף קבצים מצורפים.',
      name: 'הדר נתיבים מאיסוף קבצים מצורפים'
    },
    generatedAttachmentFileName: {
      description: 'ראה את {{tokens}} הזמינים.',
      name: 'שם קובץ מצורף שנוצר'
    },
    jpegQuality: {
      description: 'ככל שהאיכות קטנה יותר, יחס הדחיסה גדול יותר.',
      name: 'איכות JPEG'
    },
    locationForNewAttachments: {
      description: 'התחל ב-{{relativePrefix}} עבור נתיבים יחסיים לתיקיית האב של הרשימה.\nראה את {{tokens}} הזמינים.\nתיקיות נקודה כמו {{dotFolder}} אינן מומלצות, כי Obsidian אינו עוקב אחריהן. ייתכן שתצטרך להשתמש בתוסף {{unhidePlugin}} כדי לנהל אותן.',
      name: 'מיקום לקבצים מצורפים חדשים'
    },
    markdownUrlFormat: {
      description: 'פורמט עבור ה-URL שיוכנס ל-Markdown כאשר מוסיפים קובץ מצורף. הוא חל ברגע זה בלבד: קישור ש-Obsidian כותב מחדש מאוחר יותר, כאשר שמה של רשימה או של קובץ מצורף משתנה או שהם מועברים, מקבל את פורמט ברירת המחדל.\nראה את {{tokens}} הזמינים.\nהשאר ריק לשימוש בפורמט ברירת המחדל.',
      name: 'פורמט URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'האם להחיל את הגדרות תיקיית הקבצים המצורפים ושם הקובץ על קבצים מצורפים שתוספים אחרים יוצרים.\nחלק מהתוספים כותבים קובץ מצורף אל הכספת בשם משלהם, בלי לשאול את Obsidian לאן הוא שייך. כשאפשרות זו מופעלת, קובץ כזה מועבר ושמו משתנה מיד עם הופעתו.\nמטופלים רק קבצים שנוצרו בזמן שרשימה פתוחה ושרשימה מקשרת אליהם: קובץ שאף רשימה אינה מקשרת אליו הוא מידע שתוסף אחר שומר לעצמו, והוא נשאר במקום שבו נכתב. קבצים המגיעים מסנכרון או מייבוא כספת אינם מטופלים לעולם.\n{{modes}}\nהתוסף היוצר מזוהה לפי מחסנית הקריאות של הכתיבה. הזיהוי אינו מובטח: לא מזוהה שום תוסף עבור קובץ שנכתב על ידי Obsidian עצמו, על ידי לקוח סנכרון או על ידי תוסף שדוחה את הכתיבה שלו. קובץ כזה נחשב כקובץ שאינו נמצא ברשימה שלהלן.',
      name: 'שנה שם של קבצים מצורפים שיצרו תוספים אחרים'
    },
    renameAttachmentsToLowerCase: 'שנה שמות קבצים מצורפים לאותיות קטנות',
    renamedAttachmentFileName: {
      description: 'ראה את {{tokens}} הזמינים.\nהשאר ריק כדי לשמור על השם הנוכחי של הקובץ המצורף.',
      name: 'שם קובץ מצורף ששמו שונה'
    },
    resetToSampleCustomTokens: {
      message: 'האם אתה בטוח שברצונך לאפס את הטוקנים המותאמים אישיים לטוקנים המותאמים אישיים לדוגמה? השינויים שלך יאבדו.',
      title: 'אפס לטוקנים מותאמים אישיים לדוגמה'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'האם להמיר תמונות שהודבקו ל-JPEG. חל רק כאשר תוכן תמונת PNG מודבק ישירות מהלוח. בדרך כלל, להדבקת צילומי מסך.',
      name: 'האם להמיר תמונות שהודבקו ל-JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'אם מופעל, קבצים מצורפים המעובדים באמצעות הפקודות {{command}} יקבלו שמות חדשים לפי ההגדרה {{setting}}.',
      name: 'האם לשנות שמות קבצים מצורפים שנאספו'
    },
    specialCharacters: {
      description: 'תווים מיוחדים בשם תיקיית הקבצים המצורפים ובשם הקובץ, להחלפה או להסרה.\nהשאר ריק לשימור תווים מיוחדים.',
      name: 'תווים מיוחדים'
    },
    specialCharactersReplacement: {
      description: 'מחרוזת החלפה עבור תווים מיוחדים בשם תיקיית הקבצים המצורפים ובשם הקובץ.\nהשאר ריק להסרת תווים מיוחדים.',
      name: 'החלפת תווים מיוחדים'
    },
    timeoutInSeconds: {
      description: 'הזמן הקצוב בשניות עבור כל הפעולות.\nאם מוגדר {{zero}}, הזמן הקצוב לביצוע פעולות מבוטל.',
      name: 'זמן קצוב בשניות'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'שנה שם של קובץ מצורף',
    folderTitle: 'בחר תיקיית קבצים מצורפים',
    previewModal: {
      title: 'תצוגה מקדימה של קובץ מצורף \'{{fullFileName}}\''
    },
    title: 'ספק ערך עבור טוקן ההנחיה'
  },
  regularExpression: '/ביטוי רגולרי/'
};
