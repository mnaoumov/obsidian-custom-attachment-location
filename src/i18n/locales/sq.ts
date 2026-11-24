export const sq = {
  attachmentCollector: {
    confirm: 'Dëshiron të mbledhësh në mënyrë rekursive bashkëngjitjet për të gjitha shënimet në dosje?\n{{folders}}\nKy veprim nuk mund të zhbëhet.',
    progressBar: {
      message: 'Duke mbledhur bashkëngjitjet {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Duke mbledhur bashkëngjitjet...'
    }
  },
  buttons: {
    copy: 'Kopjo',
    move: 'Lëviz',
    previewAttachmentFile: 'Parashiko skedarin e bashkëngjitur',
    skip: 'Kalo'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Bashkëngjitja {{attachment}} është e referuar nga disa shënime.',
    heading: 'Duke mbledhur bashkëngjitjen e përdorur nga disa shënime',
    noPriorityWinnerReason: {
      EmptyList: 'Nuk u zhvendos sepse cilësimi {{settingName}} është bosh, prandaj asgjë nuk vendos se cili prej këtyre shënimeve e zotëron.',
      NoMatch: 'Nuk u zhvendos sepse asnjë prej këtyre shënimeve nuk përputhet me ndonjë zë në cilësimin {{settingName}}.',
      Tie: 'Nuk u zhvendos sepse disa prej këtyre shënimeve përputhen njësoj mirë me cilësimin {{settingName}}, prandaj ai nuk cakton një zotërues të vetëm.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Përdor të njëjtin veprim për bashkëngjitje të tjera problematike'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Mblidh bashkëngjitjet në dosjen aktuale',
    collectAttachmentsCurrentNote: 'Mblidh bashkëngjitjet në shënimin aktual',
    collectAttachmentsEntireVault: 'Mblidh bashkëngjitjet në gjithë depozitën'
  },
  links: {
    documentation: 'dokumentacionin',
    tokens: 'tokenat'
  },
  menuItems: {
    collectAttachmentsInFile: 'Mblidh bashkëngjitjet në skedar',
    collectAttachmentsInFiles: 'Mblidh bashkëngjitjet në skedarë'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Duke mbledhur bashkëngjitjet për \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Mbledhja e bashkëngjitjeve u anulua. Kontrolloni konsolën për detaje.',
    generatedAttachmentFileNameIsInvalid: 'Emri i gjeneruar i skedarit të bashkëngjitur \'{{path}}\' është i pavlefshëm.\n{{validationMessage}}\nKontrolloni cilësimin {{settingName}}.',
    notePathIsIgnored: 'Shtegu i shënimit është injoruar'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Anulo',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Artikuj për faqe:',
      jumpToPage: 'Shko te faqja:'
    },
    notices: {
      attachmentIsStillUsed: 'Bashkëngjitja {{attachmentPath}} ende po përdoret nga shënime të tjera. Nuk do të fshihet.',
      unhandledError: 'Ndodhi një gabim i papritur. Ju lutemi kontrolloni konsolën për më shumë informacione.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'të gjithë skedarët riemërtohen.',
        displayText: 'Të gjitha'
      },
      none: {
        description: 'emrat e tyre ruhen.',
        displayText: 'Asnjë'
      },
      onlyPastedImages: {
        description: 'vetëm imazhet e ngjitura riemërtohen. Aplikohet vetëm kur një imazh PNG ngjitet drejtpërdrejt nga clipboard. Zakonisht përdoret për pamjet e ekranit.',
        displayText: 'Vetëm imazhet e ngjitura'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'anulo mbledhjen e bashkëngjitjeve.',
        displayText: 'Anulo'
      },
      copy: {
        description: 'kopjo bashkëngjitjen në vendndodhjen e re.',
        displayText: 'Kopjo'
      },
      move: {
        description: 'lëviz bashkëngjitjen në vendndodhjen e re.',
        displayText: 'Lëviz'
      },
      prompt: {
        description: 'kërko nga përdoruesi të zgjedhë veprimin.',
        displayText: 'Kërko'
      },
      skip: {
        description: 'anashkalo bashkëngjitjen dhe vazhdo me tjetrën.',
        displayText: 'Anashkalo'
      }
    },
    defaultImageSizeDimension: {
      height: 'Gjatësia',
      width: 'Gjerësia'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Tokenat e personalizuar u komentuan pasi duhet të përditësohen me formatin e ri të prezantuar në versionin 9.0.0 të shtesës.\n// Referojuni dokumentacionit ({{customTokensDocumentationUrl}}) për më shumë informacione.',
      deprecated: 'Formati i regjistrimit të tokenave të personalizuar ndryshoi. Ju lutemi përditësoni tokenat tuaj siç duhet. Shihni {{documentation}} për më shumë informacione.'
    },
    legacyRenameAttachmentsToLowerCase: 'Cilësimi {{setting}} është i vjetruar. Përdorni në vend të tij formatin {{format}}. Shihni {{documentation}} për më shumë informacione.',
    markdownUrlFormat: {
      deprecated: 'Keni një vlerë potencialisht të gabuar të vendosur për formatin {{setting}}. Ju lutemi shihni {{documentation}} për më shumë informacione. Ky mesazh nuk do të shfaqet më.'
    },
    specialCharacters: 'Vlera e parazgjedhur e cilësimit {{setting}} u ndryshua. Vlera juaj u përditësua me vlerën e re të parazgjedhur.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Madhësia e paracaktuar e imazhit duhet të jetë në pika ose në përqindje',
      invalidCustomTokensCode: 'Kod i pavlefshëm i tokenave të personalizuar',
      invalidRegularExpression: 'Shprehje e rregullt e pavlefshme {{regExp}}',
      specialCharactersMustNotContainSlash: 'Karaketret specialë nuk duhet të përmbajnë /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Zëvendësimi i karaktereve specialë nuk duhet të përmbajë karaktere të pavlefshëm për shtegun e skedarit.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Kur bashkëngjitni skedarë:',
      name: 'Mënyra e riemërtimit të bashkëngjitjeve'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Kur bashkëngjitja e mbledhur përdoret nga disa shënime:',
      name: 'Mënyra e mbledhjes së bashkëngjitjeve të përdorura nga disa shënime'
    },
    collectedAttachmentFileName: {
      description: 'Shih {{tokens}} e disponueshëm.\nLëreni bosh për të ruajtur emrin aktual të skedarit të bashkëngjitur.',
      name: 'Emri i skedarit të bashkëngjitur të mbledhur'
    },
    customTokens: {
      description: 'Tokena të personalizuar që do të përdoren.\nShih {{documentation}} për më shumë informacione.\n⚠️ Tokenat e personalizuar mund të përmbajnë kod arbitrar JavaScript. Nëse shkruhen gabim, mund të shkaktojnë humbje të të dhënave. Përdoreni me kujdes.',
      name: 'Tokena të personalizuar'
    },
    defaultImageSize: {
      description: 'Madhësia e paracaktuar e imazhit.\nMund të specifikohet në pika ({{pixels}}) ose në përqindje të madhësisë së plotë të imazhit ({{percentage}}).\nLëreni bosh për të përdorur madhësinë origjinale të imazhit.',
      name: 'Madhësia e paracaktuar e imazhit'
    },
    duplicateNameSeparator: {
      description: 'Kur ngjisni ose tërhiqni një skedar me të njëjtin emër si një skedar ekzistues, ky ndarës do t’i shtohet emrit të skedarit.\nP.sh., kur tërhiqni skedarin {{existingFile}}, ai do të riemërtohet në {{firstAvailableName}}, {{secondAvailableName}} etj., duke marrë emrin e parë të lirë.',
      name: 'Ndarës për emra të dyfishtë'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Përjashto bashkëngjitjet nga shtigjet e mëposhtme kur ekzekutohet komanda {{command}}.\nFutni çdo shteg në një rresht të ri.\n{{pathSyntax}}\nNëse cilësimi është bosh, asnjë shteg nuk përjashtohet nga mbledhja e bashkëngjitjeve.',
      name: 'Përjashto shtigje nga mbledhja e bashkëngjitjeve'
    },
    generatedAttachmentFileName: {
      description: 'Shih {{tokens}} e disponueshëm.',
      name: 'Emri i gjeneruar i skedarit të bashkëngjitur'
    },
    jpegQuality: {
      description: 'Sa më e vogël të jetë cilësia, aq më e madhe është shkalla e kompresimit.',
      name: 'Cilësia JPEG'
    },
    locationForNewAttachments: {
      description: 'Filloni me {{relativePrefix}} për shtigje relative ndaj dosjes mëmë të shënimit.\nShih {{tokens}} e disponueshëm.\nDosjet me pikë, si {{dotFolder}}, nuk rekomandohen, sepse Obsidian nuk i ndjek. Mund t’ju duhet shtesa {{unhidePlugin}} për t’i menaxhuar.',
      name: 'Vendndodhja për bashkëngjitje të reja'
    },
    markdownUrlFormat: {
      description: 'Formati i URL-së që do të futet në Markdown kur shtohet një bashkëngjitje. Zbatohet vetëm në atë moment: një lidhje që Obsidian e rishkruan më vonë, kur një shënim ose një bashkëngjitje riemërtohet ose zhvendoset, merr formatin e parazgjedhur.\nShih {{tokens}} e disponueshëm.\nLëreni bosh për të përdorur formatin e parazgjedhur.',
      name: 'Formati i URL-së Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Nëse cilësimet e dosjes së bashkëngjitjeve dhe të emrit të skedarit zbatohen edhe për bashkëngjitjet që krijojnë shtojca të TJERA.\nDisa shtojca e shkruajnë bashkëngjitjen drejt e në kasafortë me një emër të tyrin, pa e pyetur Obsidian se ku i takon. Me këtë të aktivizuar, një skedar i tillë zhvendoset dhe riemërtohet sapo shfaqet.\nPreken vetëm skedarët e krijuar ndërsa një shënim është i hapur dhe te të cilët lidhet një shënim: një skedar te i cili nuk lidhet asnjë shënim përmban të dhëna që një shtojcë tjetër i mban për vete dhe mbetet aty ku u shkrua. Skedarët që vijnë nga një sinkronizim ose nga një import kasaforte nuk preken kurrë.\n{{modes}}\nShtojca që e krijoi skedarin identifikohet nga stiva e thirrjeve të shkrimit. Kjo bëhet sipas mundësive: asnjë shtojcë nuk identifikohet për një skedar të shkruar nga vetë Obsidian, nga një klient sinkronizimi ose nga një shtojcë që e shtyn shkrimin. Një skedar i tillë llogaritet si JO në listën më poshtë.',
      name: 'Riemërto bashkëngjitjet e krijuara nga shtojca të tjera'
    },
    renameAttachmentsToLowerCase: 'Riemërto bashkëngjitjet me shkronja të vogla',
    renamedAttachmentFileName: {
      description: 'Shih {{tokens}} e disponueshëm.\nLëreni bosh për të ruajtur emrin aktual të skedarit të bashkëngjitur.',
      name: 'Emri i skedarit të bashkëngjitur të riemërtuar'
    },
    resetToSampleCustomTokens: {
      message: 'Jeni i sigurt që doni të rivendosni tokenat e personalizuar në tokenat shembullorë? Ndryshimet tuaja do të humbasin.',
      title: 'Rivendos tek tokenat shembullorë'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Nëse imazhet e ngjitura duhet të konvertohen në JPEG. Aplikohet vetëm kur përmbajtja e një PNG ngjitet nga clipboard. Zakonisht për pamjet e ekranit.',
      name: 'Konverto imazhet e ngjitura në JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Nëse aktivizohet, bashkëngjitjet e përpunuara nga komandat {{command}} do të riemërtohen sipas cilësimit {{setting}}.',
      name: 'Riemërto bashkëngjitjet e mbledhura'
    },
    specialCharacters: {
      description: 'Karakteret speciale në emrin e dosjes dhe të skedarit të bashkëngjitjes që do të zëvendësohen ose hiqen.\nLëreni bosh për të ruajtur karakteret speciale.',
      name: 'Karaktere speciale'
    },
    specialCharactersReplacement: {
      description: 'Vargu i zëvendësimit për karakteret speciale në emrin e dosjes dhe të skedarit të bashkëngjitur.\nLëreni bosh për t’i hequr karakteret speciale.',
      name: 'Zëvendësim i karaktereve speciale'
    },
    timeoutInSeconds: {
      description: 'Kufiri i kohës në sekonda për të gjitha operacionet.\nNëse vendoset {{zero}}, kufiri i kohës për ekzekutimin e operacioneve çaktivizohet.',
      name: 'Kufiri i kohës në sekonda'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Riemërto skedarin e bashkëngjitur',
    folderTitle: 'Zgjidh dosjen e bashkëngjitjeve',
    previewModal: {
      title: 'Parashiko skedarin e bashkëngjitur \'{{fullFileName}}\''
    },
    title: 'Jepni një vlerë për tokenin e kërkesës'
  },
  regularExpression: '/shprehje e rregullt/'
};
