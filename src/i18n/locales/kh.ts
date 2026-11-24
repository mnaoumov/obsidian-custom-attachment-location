export const kh = {
  attachmentCollector: {
    confirm: 'តើអ្នកចង់ប្រមូលឯកសារភ្ជាប់សម្រាប់កំណត់ចំណាំទាំងអស់ក្នុងថត ដោយរួមទាំងថតរងទាំងអស់ (recursive) ដែរឬទេ?\n{{folders}}\nប្រតិបត្តិការនេះមិនអាចត្រឡប់វិញបានទេ។',
    progressBar: {
      message: 'កំពុងប្រក័បអទឹងដេរ {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'កំពុងប្រក័បអទឹងដេរ...'
    }
  },
  buttons: {
    copy: 'ចំលង',
    move: 'ផ្លាស់ទី',
    previewAttachmentFile: 'ប្រេវដាក់មើលឯកសារចំនាប់',
    skip: 'រំលង'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'ឯកសារភ្ជាប់ {{attachment}} ត្រូវបានយោងដោយកំណត់ចំណាំច្រើន។',
    heading: 'កំពុងប្រក័បអទឹងដេរដេលត្រូវបានប្រើដោយការចំណាំច្រើន',
    noPriorityWinnerReason: {
      EmptyList: 'វាមិនត្រូវបានផ្លាស់ទីទេ ព្រោះការកំណត់ {{settingName}} ទទេ ដូច្នេះគ្មានអ្វីសម្រេចថាកំណត់ចំណាំណាមួយក្នុងចំណោមនេះជាម្ចាស់វានោះទេ។',
      NoMatch: 'វាមិនត្រូវបានផ្លាស់ទីទេ ព្រោះគ្មានកំណត់ចំណាំណាមួយក្នុងចំណោមនេះត្រូវនឹងធាតុណាមួយក្នុងការកំណត់ {{settingName}} ឡើយ។',
      Tie: 'វាមិនត្រូវបានផ្លាស់ទីទេ ព្រោះកំណត់ចំណាំជាច្រើនក្នុងចំណោមនេះត្រូវនឹងការកំណត់ {{settingName}} ស្មើគ្នា ដូច្នេះវាមិនកំណត់ម្ចាស់តែមួយឡើយ។'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'គុរប្រើការប្រតិបត្តិការដែលដ៉កសម្រាប់អទឹងដេរចំណាប់ដេលមានបញ្ហាផ្សេងទៀត'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'កំពុងប្រក័បអទឹងដេរនៅក្នុងទឹតែកបច្ចុប្បន្ន',
    collectAttachmentsCurrentNote: 'កំពុងប្រក័បអទឹងដេរនៅក្នុងការចំណាំបច្ចុប្បន្ន',
    collectAttachmentsEntireVault: 'កំពុងប្រក័បអទឹងដេរនៅក្នុងក្និនគ្រាប់មួយ'
  },
  links: {
    documentation: 'ឯកសារយោង',
    tokens: 'សញ្ញាសម្គាល់'
  },
  menuItems: {
    collectAttachmentsInFile: 'ប្រមូលឯកសារភ្ជាប់ក្នុងឯកសារ',
    collectAttachmentsInFiles: 'ប្រមូលឯកសារភ្ជាប់ក្នុងឯកសារច្រើន'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'កំពុងប្រក័បអទឹងដេរសម្រាប់ \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'ការកំពុងប្រក័បអទឹងដេរត្រូវបានបុកចេល។ មើលកន្សោលសម្រាប់រាយលំអិត។',
    generatedAttachmentFileNameIsInvalid: 'ឈ្មោះឯកសារភ្ជាប់ដែលបានបង្កើត \'{{path}}\' មិនត្រឹមត្រូវទេ។\n{{validationMessage}}\nសូមពិនិត្យមើលការកំណត់ {{settingName}} របស់អ្នក។',
    notePathIsIgnored: 'ធ្នាំការចំណាំត្រូវបានមិនចាប់អារម្មណ៍'
  },
  obsidianLib: {
    buttons: {
      cancel: 'បុកចេល',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'ធាតុក្នុងមួយទំព័រ:',
      jumpToPage: 'លោតទៅទំព័រ:'
    },
    notices: {
      attachmentIsStillUsed: 'ឯកសារចំណាប់ {{attachmentPath}} នៅតែត្រូវបានប្រើដោយការចំណាំផ្សេងទៀត។ វានឹងមិនត្រូវបានលុបទេ។',
      unhandledError: 'កំហុសដែលមិនបានដោះស្រាយបានកើតឡើង។ សូមពិនិត្យមើលកន្សោមសម្រាប់ព័ត៌មានបន្ថែម។'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'ឯកសារទាំងអស់ត្រូវបានប្តូរឈ្មោះ។',
        displayText: 'ទាំងអស់'
      },
      none: {
        description: 'ឈ្មោះរបស់ពួកគេត្រូវបានរក្សាទុក។',
        displayText: 'គ្មាន'
      },
      onlyPastedImages: {
        description: 'តែរូបភាពដែលបានបិទប៉ុណ្ណោះត្រូវបានប្តូរឈ្មោះ។ អនុវត្តតែនៅពេលដែលមាតិការូបភាព PNG ត្រូវបានបិទពីក្តារតម្រៀបដោយផ្ទាល់។ ជាធម្មតា សម្រាប់ការបិទរូបថតអេក្រង់។',
        displayText: 'តែរូបភាពដែលបានបិទប៉ុណ្ណោះ'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'បុកចេលការប្រក័បឯកសារចំណាប់។',
        displayText: 'បុកចេល'
      },
      copy: {
        description: 'ចំលងឯកសារចំណាប់ទៅទីតាំងថ្មី។',
        displayText: 'ចំលង'
      },
      move: {
        description: 'ផ្លាស់ទីឯកសារចំណាប់ទៅទីតាំងថ្មី។',
        displayText: 'ផ្លាស់ទី'
      },
      prompt: {
        description: 'ជំរុញអ្នកប្រើឱ្យជ្រើសរើសសកម្មភាព។',
        displayText: 'ជំរុញ'
      },
      skip: {
        description: 'រំលងឯកសារចំណាប់និងបន្តទៅបន្ទាប់។',
        displayText: 'រំលង'
      }
    },
    defaultImageSizeDimension: {
      height: 'កម្ពស់',
      width: 'ទទឹង'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// សញ្ញាសម្គាល់ផ្ទាល់ខ្លួនត្រូវបានដកចេញពីមតិយោបល់ពីព្រោះពួកគេត្រូវតែបានធ្វើបច្ចុប្បន្នភាពទៅជាទម្រង់ថ្មីដែលបានណែនាំក្នុងកំណែផ្នែកបន្ថែម 9.0.0។\n// សូមមើលឯកសារយោង ({{customTokensDocumentationUrl}}) សម្រាប់ព័ត៌មានបន្ថែម។',
      deprecated: 'ទម្រង់នៃការចុះឈ្មោះសញ្ញាសម្គាល់ផ្ទាល់ខ្លួនបានផ្លាស់ប្តូរ។ សូមធ្វើបច្ចុប្បន្នភាពសញ្ញាសម្គាល់របស់អ្នកឱ្យស្របតាម។ សូមមើល {{documentation}} សម្រាប់ព័ត៌មានបន្ថែម។'
    },
    legacyRenameAttachmentsToLowerCase: 'ការកំណត់ {{setting}} លែងប្រើហើយ។ សូមប្រើទម្រង់ {{format}} ជំនួសវិញ។ សូមមើល {{documentation}} សម្រាប់ព័ត៌មានបន្ថែម។',
    markdownUrlFormat: {
      deprecated: 'អ្នកប្រហែលជាបានកំណត់តម្លៃមិនត្រឹមត្រូវសម្រាប់ទម្រង់ {{setting}}។ សូមមើល {{documentation}} សម្រាប់ព័ត៌មានបន្ថែម។ សារនេះនឹងមិនត្រូវបានបង្ហាញម្តងទៀតទេ។'
    },
    specialCharacters: 'តម្លៃលំនាំដើមនៃការកំណត់ {{setting}} បានផ្លាស់ប្តូរ។ តម្លៃការកំណត់របស់អ្នកត្រូវបានធ្វើបច្ចុប្បន្នភាពទៅតម្លៃលំនាំដើមថ្មី។',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'ទំហំរូបភាពលំនាំដើមត្រូវតែជាភាគរយ ឬ ភីកសែល',
      invalidCustomTokensCode: 'កូដសញ្ញាសម្គាល់ផ្ទាល់ខ្លួនមិនត្រឹមត្រូវ',
      invalidRegularExpression: 'កន្សោមធម្មតាមិនត្រឹមត្រូវ {{regExp}}',
      specialCharactersMustNotContainSlash: 'តួអក្សរពិសេសមិនត្រូវមាន /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'ការជំនួសតួអក្សរពិសេសមិនត្រូវមានតួអក្សរផ្លូវឈ្មោះឯកសារមិនត្រឹមត្រូវ។'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'នៅពេលភ្ជាប់ឯកសារ:',
      name: 'របៀបប្តូរឈ្មោះឯកសារចំណាប់'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'នៅពេលឯកសារភ្ជាប់ដែលបានប្រមូលត្រូវបានប្រើដោយកំណត់ចំណាំច្រើន:',
      name: 'របៀបប្រក័បឯកសារចំណាប់ដែលប្រើដោយការចំណាំច្រើន'
    },
    collectedAttachmentFileName: {
      description: 'មើល {{tokens}} ដែលមាន។\nទុកទទេដើម្បីរក្សាឈ្មោះបច្ចុប្បន្នរបស់ឯកសារភ្ជាប់។',
      name: 'ឈ្មោះឯកសារចំណាប់ដែលបានប្រក័ប'
    },
    customTokens: {
      description: 'សញ្ញាសម្គាល់ផ្ទាល់ខ្លួនដែលត្រូវប្រើ។\nមើល {{documentation}} សម្រាប់ព័ត៌មានបន្ថែម។\n⚠️ សញ្ញាសម្គាល់ផ្ទាល់ខ្លួនអាចជាកូដ JavaScript បំពាន។ ប្រសិនបើសរសេរមិនល្អ វាអាចបណ្តាលឱ្យបាត់បង់ទិន្នន័យ។ ប្រើវាតាមហានុភាពរបស់អ្នក។',
      name: 'សញ្ញាសម្គាល់ផ្ទាល់ខ្លួន'
    },
    defaultImageSize: {
      description: 'ទំហំរូបភាពលំនាំដើម។\nអាចកំណត់ជាភីកសែល ({{pixels}}) ឬជាភាគរយនៃទំហំរូបភាពពេញ ({{percentage}})។\nទុកឲ្យទទេដើម្បីប្រើទំហំរូបភាពដើម។',
      name: 'ទំហំរូបភាពលំនាំដើម'
    },
    duplicateNameSeparator: {
      description: 'នៅពេលអ្នកបិទ ឬទាញឯកសារដែលមានឈ្មោះដូចគ្នានឹងឯកសារដែលមានស្រាប់ អ្នកបំបែកនេះនឹងត្រូវបានបន្ថែមទៅឈ្មោះឯកសារ។\nឧទាហរណ៍ នៅពេលអ្នកទាញឯកសារ {{existingFile}} វានឹងត្រូវបានប្តូរឈ្មោះទៅជា {{firstAvailableName}}, {{secondAvailableName}} ជាដើម តាមឈ្មោះដំបូងដែលនៅទំនេរ។',
      name: 'អ្នកបំបែកឈ្មោះដូចគ្នា'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'ដកឯកសារភ្ជាប់ពីផ្លូវខាងក្រោមចេញ នៅពេលពាក្យបញ្ជា {{command}} ត្រូវបានប្រតិបត្តិ។\nបញ្ចូលផ្លូវនីមួយៗនៅលើបន្ទាត់ថ្មី។\n{{pathSyntax}}\nប្រសិនបើការកំណត់ទទេ គ្មានផ្លូវណាមួយត្រូវបានដកចេញពីការប្រមូលឯកសារភ្ជាប់ទេ។',
      name: 'ដកចេញផ្លូវពីការប្រក័បឯកសារចំណាប់'
    },
    generatedAttachmentFileName: {
      description: 'មើល {{tokens}} ដែលមាន។',
      name: 'ឈ្មោះឯកសារចំណាប់ដែលបានបង្កើត'
    },
    jpegQuality: {
      description: 'គុណភាពតូចជាង សមាមាត្របង្ហាប់កាន់តែធំ។',
      name: 'គុណភាព JPEG'
    },
    locationForNewAttachments: {
      description: 'ចាប់ផ្តើមដោយ {{relativePrefix}} សម្រាប់ផ្លូវដែលទាក់ទងនឹងថតមេនៃកំណត់ចំណាំ។\nមើល {{tokens}} ដែលមាន។\nថតដែលចាប់ផ្តើមដោយចំណុច ដូចជា {{dotFolder}} មិនត្រូវបានណែនាំទេ ពីព្រោះ Obsidian មិនតាមដានពួកវា។ អ្នកប្រហែលជាត្រូវប្រើផ្នែកបន្ថែម {{unhidePlugin}} ដើម្បីគ្រប់គ្រងពួកវា។',
      name: 'ទីតាំងសម្រាប់ឯកសារចំណាប់ថ្មី'
    },
    markdownUrlFormat: {
      description: 'ទម្រង់សម្រាប់ URL ដែលនឹងត្រូវបានបញ្ចូលទៅក្នុង Markdown នៅពេលបន្ថែមឯកសារភ្ជាប់។ វាត្រូវបានអនុវត្តតែនៅពេលនោះប៉ុណ្ណោះ៖ តំណដែល Obsidian សរសេរឡើងវិញនៅពេលក្រោយ នៅពេលកំណត់ចំណាំ ឬឯកសារភ្ជាប់ត្រូវបានប្តូរឈ្មោះ ឬផ្លាស់ទី នឹងទទួលបានទម្រង់លំនាំដើម។\nមើល {{tokens}} ដែលមាន។\nទុកទទេដើម្បីប្រើទម្រង់លំនាំដើម។',
      name: 'ទម្រង់ URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'ថាតើត្រូវអនុវត្តការកំណត់ថតឯកសារភ្ជាប់ និងឈ្មោះឯកសារ ទៅលើឯកសារភ្ជាប់ដែលកម្មវិធីជំនួយផ្សេងបង្កើតឬអត់។\nកម្មវិធីជំនួយខ្លះសរសេរឯកសារភ្ជាប់ចូលក្នុងឃ្លាំងដោយប្រើឈ្មោះផ្ទាល់ខ្លួន ដោយមិនសួរ Obsidian ថាវាគួរនៅកន្លែងណា។ ពេលបើកមុខងារនេះ ឯកសារបែបនេះនឹងត្រូវផ្លាស់ទី និងប្តូរឈ្មោះភ្លាមៗបន្ទាប់ពីវាលេចឡើង។\nមានតែឯកសារដែលបង្កើតពេលកំណត់ចំណាំកំពុងបើក ហើយមានតំណពីកំណត់ចំណាំ ប៉ុណ្ណោះដែលត្រូវប៉ះពាល់៖ ឯកសារដែលគ្មានកំណត់ចំណាំណាភ្ជាប់តំណទៅ គឺជាទិន្នន័យដែលកម្មវិធីជំនួយផ្សេងរក្សាទុកសម្រាប់ខ្លួនវា ហើយនៅដដែលកន្លែងដែលវាត្រូវបានសរសេរ។ ឯកសារដែលមកពីការធ្វើសមកាលកម្ម ឬការនាំចូលឃ្លាំង មិនដែលត្រូវប៉ះពាល់ឡើយ។\n{{modes}}\nកម្មវិធីជំនួយដែលបង្កើតឯកសារ ត្រូវបានកំណត់អត្តសញ្ញាណពី call stack នៃការសរសេរ។ នេះគ្រាន់តែជាការព្យាយាមល្អបំផុតប៉ុណ្ណោះ៖ គ្មានកម្មវិធីជំនួយណាត្រូវបានកំណត់អត្តសញ្ញាណសម្រាប់ឯកសារដែលសរសេរដោយ Obsidian ផ្ទាល់ ដោយកម្មវិធីធ្វើសមកាលកម្ម ឬដោយកម្មវិធីជំនួយដែលពន្យារការសរសេររបស់វា។ ឯកសារបែបនេះត្រូវបានចាត់ទុកថា មិនស្ថិតនៅក្នុងបញ្ជីខាងក្រោមទេ។',
      name: 'ប្តូរឈ្មោះឯកសារភ្ជាប់ដែលកម្មវិធីជំនួយផ្សេងបានបង្កើត'
    },
    renameAttachmentsToLowerCase: 'ប្តូរឈ្មោះឯកសារចំណាប់ទៅជាអក្សរតូច',
    renamedAttachmentFileName: {
      description: 'មើល {{tokens}} ដែលមាន។\nទុកទទេដើម្បីរក្សាឈ្មោះបច្ចុប្បន្នរបស់ឯកសារភ្ជាប់។',
      name: 'ឈ្មោះឯកសារចំណាប់ដែលបានប្តូរឈ្មោះ'
    },
    resetToSampleCustomTokens: {
      message: 'តើអ្នកប្រាកដថាចង់កំណត់ឡើងវិញសញ្ញាសម្គាល់ផ្ទាល់ខ្លួនទៅសញ្ញាសម្គាល់ផ្ទាល់ខ្លួនគំរូ? ការផ្លាស់ប្តូររបស់អ្នកនឹងបាត់បង់។',
      title: 'កំណត់ឡើងវិញទៅសញ្ញាសម្គាល់ផ្ទាល់ខ្លួនគំរូ'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'តើត្រូវប្តូររូបភាពដែលបានបិទទៅ JPEG ឬទេ។ អនុវត្តតែនៅពេលដែលមាតិការូបភាព PNG ត្រូវបានបិទពីក្តារតម្រៀបដោយផ្ទាល់។ ជាធម្មតា សម្រាប់ការបិទរូបថតអេក្រង់។',
      name: 'តើត្រូវប្តូររូបភាពដែលបានបិទទៅ JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'ប្រសិនបើបើក ឯកសារភ្ជាប់ដែលបានដំណើរការតាមរយៈពាក្យបញ្ជា {{command}} នឹងត្រូវបានប្តូរឈ្មោះតាមការកំណត់ {{setting}}។',
      name: 'តើត្រូវប្តូរឈ្មោះឯកសារចំណាប់ដែលបានប្រក័ប'
    },
    specialCharacters: {
      description: 'តួអក្សរពិសេសក្នុងឈ្មោះថត និងឈ្មោះឯកសារភ្ជាប់ ដែលត្រូវជំនួស ឬដកចេញ។\nទុកទទេដើម្បីរក្សាទុកតួអក្សរពិសេស។',
      name: 'តួអក្សរពិសេស'
    },
    specialCharactersReplacement: {
      description: 'ខ្សែអក្សរជំនួសសម្រាប់តួអក្សរពិសេសក្នុងឈ្មោះថត និងឈ្មោះឯកសារភ្ជាប់។\nទុកទទេដើម្បីដកចេញតួអក្សរពិសេស។',
      name: 'ការជំនួសតួអក្សរពិសេស'
    },
    timeoutInSeconds: {
      description: 'ពេលវេលាអស់សម្រាប់ប្រតិបត្តិការទាំងអស់ (វិនាទី)។\nប្រសិនបើកំណត់ជា {{zero}} ពេលវេលាអស់នៃការប្រតិបត្តិប្រតិបត្តិការនឹងត្រូវបានបិទ។',
      name: 'ពេលវេលាអស់ (វិនាទី)'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'ប្តូរឈ្មោះឯកសារភ្ជាប់',
    folderTitle: 'ជ្រើសរើសថតឯកសារភ្ជាប់',
    previewModal: {
      title: 'ប្រេវដាក់មើលឯកសារចំណាប់ \'{{fullFileName}}\''
    },
    title: 'ផ្តល់តម្លៃសម្រាប់សញ្ញាសម្គាល់ជំរុញ'
  },
  regularExpression: '/កន្សោមធម្មតា/'
};
