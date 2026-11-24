export const ne = {
  attachmentCollector: {
    confirm: 'के तपाईं निम्न फोल्डरहरूभित्रका सबै नोटहरूका लागि संलग्नकहरूलाई पुनरावर्ती रूपमा सङ्कलन गर्न चाहनुहुन्छ?\n{{folders}}\nयो कार्य उल्ट्याउन सकिँदैन।',
    progressBar: {
      message: 'संलग्नकहरू संकलन गर्दै {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'संलग्नकहरू संकलन गर्दै...'
    }
  },
  buttons: {
    copy: 'प्रतिलिपि गर्नुहोस्',
    move: 'सार्नुहोस्',
    previewAttachmentFile: 'संलग्नक फाइल पूर्वावलोकन',
    skip: 'फाल्नुहोस्'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'संलग्नक {{attachment}} धेरै नोटहरूद्वारा सन्दर्भित छ।',
    heading: 'धेरै नोटहरूद्वारा प्रयोग हुने संलग्नक संकलन गर्दै',
    noPriorityWinnerReason: {
      EmptyList: '{{settingName}} सेटिङ खाली भएकाले यो सारिएन, त्यसैले यी नोटहरूमध्ये कुनले यसलाई ओगट्छ भन्ने कुरा केहीले पनि निर्णय गर्दैन।',
      NoMatch: 'यी नोटहरूमध्ये कुनै पनि {{settingName}} सेटिङको कुनै प्रविष्टिसँग मेल नखाएकाले यो सारिएन।',
      Tie: 'यी नोटहरूमध्ये धेरै {{settingName}} सेटिङसँग समान रूपमा मेल खाएकाले एउटै मालिक तोकिन नसकेर यो सारिएन।'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'अन्य समस्यायुक्त संलग्नकहरूका लागि एउटानै कार्य प्रयोग गर्नुपर्यो'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'हालको फोल्डरमा संलग्नकहरू संकलन गर्नुहोस्',
    collectAttachmentsCurrentNote: 'हालको नोटमा संलग्नकहरू संकलन गर्नुहोस्',
    collectAttachmentsEntireVault: 'सम्पूर्ण भाल्टमा संलग्नकहरू संकलन गर्नुहोस्'
  },
  links: {
    documentation: 'कागजात',
    tokens: 'टोकनहरू'
  },
  menuItems: {
    collectAttachmentsInFile: 'फाइलमा संलग्नकहरू सङ्कलन गर्नुहोस्',
    collectAttachmentsInFiles: 'फाइलहरूमा संलग्नकहरू सङ्कलन गर्नुहोस्'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: '\'{{noteFilePath}}\' का लागि संलग्नकहरू संकलन गर्दै',
    collectingAttachmentsCancelled: 'संलग्नक संकलन रद्द गरियो। विस्तृत जानकारीका लागि कन्सोल हेर्नुहोस्।',
    generatedAttachmentFileNameIsInvalid: 'उत्पन्न संलग्नक फाइल नाम \'{{path}}\' अमान्य छ।\n{{validationMessage}}\nआफ्नो {{settingName}} सेटिङ जाँच्नुहोस्।',
    notePathIsIgnored: 'नोट पाथ बेवास्ता गरिएको छ'
  },
  obsidianLib: {
    buttons: {
      cancel: 'रद्द गर्नुहोस्',
      ok: 'ठिक छ'
    },
    dataview: {
      itemsPerPage: 'प्रति पृष्ठ वस्तुहरू:',
      jumpToPage: 'पृष्ठमा जानुहोस्:'
    },
    notices: {
      attachmentIsStillUsed: 'संलग्नक {{attachmentPath}} अझै पनि अन्य नोटहरूद्वारा प्रयोग हुँदैछ। यो मेटिनेछैन।',
      unhandledError: 'एउटा नसुल्झिएको त्रुटि भयो। कृपया थप जानकारीका लागि कन्सोल जाँच्नुहोस्।'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'सबै फाइलहरू पुनः नामकरण गरिन्छन्।',
        displayText: 'सबै'
      },
      none: {
        description: 'तिनीहरूका नामहरू संरक्षित हुन्छन्।',
        displayText: 'कुनै पनि होइन'
      },
      onlyPastedImages: {
        description: 'केवल टाँसिएका छविहरू पुनः नामकरण गरिन्छन्। यो केवल तब लागू हुन्छ जब PNG छवि सामग्री क्लिपबोर्डबाट सीधै टाँसिएको हुन्छ। सामान्यतया, स्क्रिनशट टाँस्नका लागि।',
        displayText: 'केवल टाँसिएका छविहरू'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'संलग्नक संकलन रद्द गर्नुहोस्।',
        displayText: 'रद्द गर्नुहोस्'
      },
      copy: {
        description: 'संलग्नकलाई नयाँ स्थानमा प्रतिलिपि गर्नुहोस्।',
        displayText: 'प्रतिलिपि गर्नुहोस्'
      },
      move: {
        description: 'संलग्नकलाई नयाँ स्थानमा सार्नुहोस्।',
        displayText: 'सार्नुहोस्'
      },
      prompt: {
        description: 'प्रयोगकर्तालाई कार्य छनोट गर्न प्रेरित गर्नुहोस्।',
        displayText: 'प्रेरित गर्नुहोस्'
      },
      skip: {
        description: 'संलग्नकलाई छोड्नुहोस् र अर्कोमा जानुहोस्।',
        displayText: 'छोड्नुहोस्'
      }
    },
    defaultImageSizeDimension: {
      height: 'उचाइ',
      width: 'चौडाइ'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// कस्टम टोकनहरू टिप्पणी गरिएका छन् किनभने तिनीहरूलाई प्लगइन संस्करण 9.0.0 मा परिचय गरिएको नयाँ ढाँचामा अपडेट गर्नुपर्छ।\n// थप जानकारीका लागि कागजात ({{customTokensDocumentationUrl}}) हेर्नुहोस्।',
      deprecated: 'कस्टम टोकन दर्ताको ढाँचा परिवर्तन भएको छ। कृपया तपाईँका टोकनहरूलाई तदनुसार अपडेट गर्नुहोस्। थप जानकारीका लागि {{documentation}} हेर्नुहोस्।'
    },
    legacyRenameAttachmentsToLowerCase: '{{setting}} सेटिङ पुरानो भइसकेको छ। यसको सट्टा {{format}} ढाँचा प्रयोग गर्नुहोस्। थप जानकारीका लागि {{documentation}} हेर्नुहोस्।',
    markdownUrlFormat: {
      deprecated: 'तपाईँले {{setting}} ढाँचाका लागि सम्भवतः गलत मान सेट गर्नुभएको छ। कृपया थप जानकारीका लागि {{documentation}} हेर्नुहोस्। यो सन्देश फेरि देखाइनेछैन।'
    },
    specialCharacters: '{{setting}} सेटिङको पूर्वनिर्धारित मान परिवर्तन भयो। तपाईँको सेटिङ मान नयाँ पूर्वनिर्धारित मानमा अपडेट गरियो।',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'पूर्वनिर्धारित तस्वीरको आकार पिक्सेल या प्रतिशतमा हुनुपर्छ',
      invalidCustomTokensCode: 'अमान्य कस्टम टोकन कोड',
      invalidRegularExpression: 'अमान्य नियमित अभिव्यक्ति {{regExp}}',
      specialCharactersMustNotContainSlash: 'विशेष अक्षरहरूमा / हुनुहुन्न',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'विशेष अक्षर प्रतिस्थापनमा अमान्य फाइल नाम पाथ अक्षरहरू हुनुहुन्न।'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'फाइलहरू संलग्न गर्दा:',
      name: 'संलग्नक पुनः नामकरण मोड'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'जब संकलित संलग्नक धेरै नोटहरूद्वारा प्रयोग हुन्छ:',
      name: 'धेरै नोटहरूद्वारा प्रयोग हुने संलग्नक संकलन मोड'
    },
    collectedAttachmentFileName: {
      description: 'उपलब्ध {{tokens}} हेर्नुहोस्।\nसंलग्नकको हालको फाइल नाम राख्न खाली छोड्नुहोस्।',
      name: 'संकलित संलग्नक फाइल नाम'
    },
    customTokens: {
      description: 'प्रयोग गर्नका लागि कस्टम टोकनहरू।\nथप जानकारीका लागि {{documentation}} हेर्नुहोस्।\n⚠️ कस्टम टोकनहरू मनमाना JavaScript कोड हुन सक्छन्। यदि राम्रोसँग लेखिएको छैन भने, यसले डाटा हानि गर्न सक्छ। आफ्नै जोखिममा प्रयोग गर्नुहोस्।',
      name: 'कस्टम टोकनहरू'
    },
    defaultImageSize: {
      description: 'पूर्वनिर्धारित तस्वीरको आकार।\nपिक्सेलमा ({{pixels}}) वा पूर्ण तस्वीरको आकारको प्रतिशतमा ({{percentage}}) निर्दिष्ट गर्न सकिन्छ।\nमूल तस्वीरको आकार प्रयोग गर्न खाली राख्नुहोस्।',
      name: 'पूर्वनिर्धारित तस्वीरको आकार'
    },
    duplicateNameSeparator: {
      description: 'जब तपाईँ अवस्थित फाइलकै नाम भएको फाइल टाँस्नु वा तान्नुहुन्छ, यो विभाजक फाइल नाममा थपिनेछ।\nउदाहरणका लागि, जब तपाईँ फाइल {{existingFile}} तान्नुहुन्छ, पहिलो उपलब्ध नाम लिँदै यसलाई {{firstAvailableName}}, {{secondAvailableName}} आदिमा पुनः नामकरण गरिनेछ।',
      name: 'डुप्लिकेट नाम विभाजक'
    },
    excludePathsFromAttachmentCollecting: {
      description: '{{command}} आदेश कार्यान्वयन गर्दा निम्न पाथहरूका संलग्नकहरू बाहिर राख्नुहोस्।\nप्रत्येक पाथलाई नयाँ लाइनमा राख्नुहोस्।\n{{pathSyntax}}\nयदि सेटिङ खाली छ भने, संलग्नक संकलनबाट कुनै पनि पाथ बाहिर राखिँदैन।',
      name: 'संलग्नक संकलनबाट पाथहरू बाहिर निकाल्नुहोस्'
    },
    generatedAttachmentFileName: {
      description: 'उपलब्ध {{tokens}} हेर्नुहोस्।',
      name: 'उत्पन्न संलग्नक फाइल नाम'
    },
    jpegQuality: {
      description: 'गुणस्तर जति सानो, कम्प्रेसन अनुपात त्यति ठूलो।',
      name: 'JPEG गुणस्तर'
    },
    locationForNewAttachments: {
      description: 'नोटको मूल फोल्डरसापेक्ष पाथका लागि {{relativePrefix}} बाट सुरु गर्नुहोस्।\nउपलब्ध {{tokens}} हेर्नुहोस्।\n{{dotFolder}} जस्ता डट-फोल्डरहरू सिफारिस गरिँदैनन्, किनभने Obsidian ले तिनीहरूलाई ट्र्याक गर्दैन। तिनीहरूलाई व्यवस्थापन गर्न तपाईँलाई {{unhidePlugin}} प्लगइन चाहिन सक्छ।',
      name: 'नयाँ संलग्नकहरूका लागि स्थान'
    },
    markdownUrlFormat: {
      description: 'संलग्नक थपिँदा मार्कडाउनमा समावेश गरिने यूआरएलका लागि ढाँचा। यो त्यही बेला मात्र लागू हुन्छ: नोट वा संलग्नकको नाम परिवर्तन गर्दा वा सार्दा Obsidian ले पछि पुनः लेख्ने लिङ्कले पूर्वनिर्धारित ढाँचा पाउँछ।\nउपलब्ध {{tokens}} हेर्नुहोस्।\nपूर्वनिर्धारित ढाँचा प्रयोग गर्नका लागि खाली छोड्नुहोस्।',
      name: 'मार्कडाउन यूआरएल ढाँचा'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'अन्य प्लगइनहरूले सिर्जना गरेका संलग्नकहरूमा पनि संलग्नक फोल्डर र फाइल नामका सेटिङहरू लागू गर्ने कि नगर्ने।\nकेही प्लगइनहरूले संलग्नक कहाँ पर्छ भनेर Obsidian लाई नसोधी आफ्नै नाममा भल्टमा लेख्छन्। यो सक्षम भएमा, त्यस्तो फाइल देखिनेबित्तिकै सारिन्छ र नाम परिवर्तन गरिन्छ।\nनोट खुला रहेको बेला सिर्जना भएका र कुनै नोटबाट लिङ्क गरिएका फाइलहरू मात्र छोइन्छन्: कुनै पनि नोटले लिङ्क नगरेको फाइल अर्को प्लगइनले आफ्नै लागि राखेको डाटा हो, र जहाँ लेखिएको थियो त्यहीँ रहन्छ। सिंक वा भल्ट आयातबाट आउने फाइलहरू कहिल्यै छोइँदैनन्।\n{{modes}}\nफाइल सिर्जना गर्ने प्लगइन लेखाइको कल स्ट्याकबाट पहिचान गरिन्छ। यो सकेसम्मको प्रयास मात्र हो: Obsidian आफैँले, सिंक क्लाइन्टले, वा आफ्नो लेखाइ ढिलो गर्ने प्लगइनले लेखेको फाइलका लागि कुनै प्लगइन पहिचान हुँदैन। त्यस्तो फाइललाई तलको सूचीमा नभएको मानिन्छ।',
      name: 'अन्य प्लगइनहरूले सिर्जना गरेका संलग्नकहरूको नाम परिवर्तन गर्नुहोस्'
    },
    renameAttachmentsToLowerCase: 'संलग्नकहरूलाई सानो अक्षरमा पुनः नामकरण गर्नुहोस्',
    renamedAttachmentFileName: {
      description: 'उपलब्ध {{tokens}} हेर्नुहोस्।\nसंलग्नकको हालको फाइल नाम राख्न खाली छोड्नुहोस्।',
      name: 'पुनः नामकरण गरिएको संलग्नक फाइल नाम'
    },
    resetToSampleCustomTokens: {
      message: 'के तपाईँ कस्टम टोकनहरूलाई नमुना कस्टम टोकनहरूमा रिसेट गर्न चाहनुहुन्छ? तपाईँका परिवर्तनहरू हराउनेछन्।',
      title: 'नमुना कस्टम टोकनहरूमा रिसेट गर्नुहोस्'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'के टाँसिएका छविहरूलाई JPEG मा रूपान्तरण गर्ने। यो केवल तब लागू हुन्छ जब PNG छवि सामग्री क्लिपबोर्डबाट सीधै टाँसिएको हुन्छ। सामान्यतया, स्क्रिनशट टाँस्नका लागि।',
      name: 'टाँसिएका छविहरूलाई JPEG मा रूपान्तरण गर्नुपर्छ'
    },
    shouldRenameCollectedAttachments: {
      description: 'यदि सक्षम गरिएको छ भने, {{command}} आदेशहरू मार्फत प्रशोधित संलग्नकहरू {{setting}} सेटिङ अनुसार पुनः नामकरण गरिनेछन्।',
      name: 'संकलित संलग्नकहरू पुनः नामकरण गर्नुपर्छ'
    },
    specialCharacters: {
      description: 'संलग्नक फोल्डर र फाइल नाममा प्रतिस्थापन वा हटाउनका लागि विशेष अक्षरहरू।\nविशेष अक्षरहरू संरक्षित गर्नका लागि खाली छोड्नुहोस्।',
      name: 'विशेष अक्षरहरू'
    },
    specialCharactersReplacement: {
      description: 'संलग्नक फोल्डर र फाइल नाममा विशेष अक्षरहरूका लागि प्रतिस्थापन स्ट्रिङ।\nविशेष अक्षरहरू हटाउनका लागि खाली छोड्नुहोस्।',
      name: 'विशेष अक्षरहरू प्रतिस्थापन'
    },
    timeoutInSeconds: {
      description: 'सबै कार्यहरूका लागि सेकेन्डमा टाइमआउट।\nयदि {{zero}} सेट गरिएको छ भने, कार्यहरूको कार्यान्वयन टाइमआउट अक्षम हुन्छ।',
      name: 'सेकेन्डमा टाइमआउट'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'संलग्नक फाइलको नाम परिवर्तन गर्नुहोस्',
    folderTitle: 'संलग्नक फोल्डर छान्नुहोस्',
    previewModal: {
      title: 'संलग्नक फाइल \'{{fullFileName}}\' को पूर्वावलोकन'
    },
    title: 'प्रोम्प्ट टोकनका लागि मान प्रदान गर्नुहोस्'
  },
  regularExpression: '/नियमित अभिव्यक्ति/'
};
