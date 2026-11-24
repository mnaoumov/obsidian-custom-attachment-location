export const hu = {
  attachmentCollector: {
    confirm: 'Szeretnéd rekurzívan összegyűjteni a mellékleteket a mappákban lévő összes jegyzethez?\n{{folders}}\nEz a művelet nem vonható vissza.',
    progressBar: {
      message: 'Mellékletek összegyűjtése {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Mellékletek összegyűjtése...'
    }
  },
  buttons: {
    copy: 'Másolás',
    move: 'Áthelyezés',
    previewAttachmentFile: 'Melléklet fájl előnézete',
    skip: 'Kihagyás'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'A(z) {{attachment}} mellékletre több jegyzet is hivatkozik.',
    heading: 'Több jegyzet által használt melléklet gyűjtése',
    noPriorityWinnerReason: {
      EmptyList: 'Nem került áthelyezésre, mert a(z) {{settingName}} beállítás üres, így semmi sem dönti el, hogy e jegyzetek közül melyikhez tartozik.',
      NoMatch: 'Nem került áthelyezésre, mert e jegyzetek egyike sem felel meg a(z) {{settingName}} beállítás egyetlen bejegyzésének sem.',
      Tie: 'Nem került áthelyezésre, mert e jegyzetek közül több is ugyanannyira megfelel a(z) {{settingName}} beállításnak, így az nem jelöl ki egyetlen tulajdonost.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Ugyanazt a műveletet kell használni más problémás mellékletek esetében'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Mellékletek gyűjtése a jelenlegi mappából',
    collectAttachmentsCurrentNote: 'Mellékletek gyűjtése a jelenlegi jegyzetből',
    collectAttachmentsEntireVault: 'Mellékletek gyűjtése a teljes tárolóból'
  },
  links: {
    documentation: 'dokumentációt',
    tokens: 'tokeneket'
  },
  menuItems: {
    collectAttachmentsInFile: 'Mellékletek összegyűjtése a fájlban',
    collectAttachmentsInFiles: 'Mellékletek összegyűjtése a fájlokban'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Mellékletek gyűjtése a következőhöz: \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Melléklet gyűjtés megszakítva. Részletekért lásd a konzolt.',
    generatedAttachmentFileNameIsInvalid: 'A(z) \'{{path}}\' generált melléklet fájlnév érvénytelen.\n{{validationMessage}}\nEllenőrizd a(z) {{settingName}} beállítást.',
    notePathIsIgnored: 'A jegyzet elérési útja figyelmen kívül marad'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Mégse',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Elemek oldalanként:',
      jumpToPage: 'Ugrás az oldalra:'
    },
    notices: {
      attachmentIsStillUsed: 'A {{attachmentPath}} mellékletet még mindig más jegyzetek használják. Nem lesz törölve.',
      unhandledError: 'Nem kezelt hiba történt. További információért ellenőrizd a konzolt.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'minden fájl átnevezésre kerül.',
        displayText: 'Minden'
      },
      none: {
        description: 'neveik megmaradnak.',
        displayText: 'Egyik sem'
      },
      onlyPastedImages: {
        description: 'csak a beillesztett képek kerülnek átnevezésre. Csak akkor érvényes, amikor a PNG kép tartalma közvetlenül a vágólapról van beillesztve. Jellemzően képernyőképek beillesztésénél.',
        displayText: 'Csak beillesztett képek'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'melléklet gyűjtés megszakítása.',
        displayText: 'Mégse'
      },
      copy: {
        description: 'melléklet másolása az új helyre.',
        displayText: 'Másolás'
      },
      move: {
        description: 'melléklet áthelyezése az új helyre.',
        displayText: 'Áthelyezés'
      },
      prompt: {
        description: 'felhasználó kérése a művelet kiválasztására.',
        displayText: 'Kérés'
      },
      skip: {
        description: 'melléklet kihagyása és folytatás a következővel.',
        displayText: 'Kihagyás'
      }
    },
    defaultImageSizeDimension: {
      height: 'Magasság',
      width: 'Szélesség'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Az egyéni tokenek kommentbe kerültek, mert frissíteni kell őket a 9.0.0 verzióban bevezetett új formátumra.\n// További információért lásd a dokumentációt ({{customTokensDocumentationUrl}}).',
      deprecated: 'Az egyéni token regisztráció formátuma megváltozott. Kérjük, frissítsd a tokenjeidet ennek megfelelően. További információért lásd a {{documentation}}.'
    },
    legacyRenameAttachmentsToLowerCase: 'A(z) {{setting}} beállítás elavult. Használd helyette a(z) {{format}} formátumot. További információért lásd a {{documentation}}.',
    markdownUrlFormat: {
      deprecated: 'Lehet, hogy hibás értéket állítottál be a(z) {{setting}} formátumhoz. További információért lásd a {{documentation}}. Ez az üzenet nem jelenik meg újra.'
    },
    specialCharacters: 'A(z) {{setting}} beállítás alapértelmezett értéke megváltozott. A beállításod értéke frissült az új alapértelmezett értékre.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Az alapértelmezett képméretnek pixelben vagy százalékban kell megadva lennie',
      invalidCustomTokensCode: 'Érvénytelen egyéni token kód',
      invalidRegularExpression: 'Érvénytelen reguláris kifejezés {{regExp}}',
      specialCharactersMustNotContainSlash: 'A speciális karakterek nem tartalmazhatnak / jelet',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'A speciális karakterek helyettesítése nem tartalmazhat érvénytelen fájlnév elérési út karaktereket.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Fájlok csatolásakor:',
      name: 'Melléklet átnevezési mód'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Amikor a gyűjtött mellékletet több jegyzet használja:',
      name: 'Több jegyzet által használt melléklet gyűjtési mód'
    },
    collectedAttachmentFileName: {
      description: 'Lásd az elérhető {{tokens}}.\nHagyd üresen a melléklet jelenlegi fájlnevének megtartásához.',
      name: 'Gyűjtött melléklet fájlnév'
    },
    customTokens: {
      description: 'Használandó egyéni tokenek.\nTovábbi információért lásd a {{documentation}}.\n⚠️ Az egyéni tokenek tetszőleges JavaScript kód lehetnek. Ha rosszul írták, adatvesztést okozhatnak. Saját felelősségre használd.',
      name: 'Egyéni tokenek'
    },
    defaultImageSize: {
      description: 'Az alapértelmezett képméret.\nMegadható pixelben ({{pixels}}) vagy a teljes képméret százalékában ({{percentage}}).\nHagyd üresen az eredeti képméret használatához.',
      name: 'Alapértelmezett képméret'
    },
    duplicateNameSeparator: {
      description: 'Amikor egy meglévő fájllal azonos nevű fájlt illesztesz be vagy húzol be, ez az elválasztó kerül a fájlnévhez.\nPl. amikor a(z) {{existingFile}} fájlt húzod be, az új neve {{firstAvailableName}}, {{secondAvailableName}} stb. lesz, az első még szabad név szerint.',
      name: 'Duplikált név elválasztó'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Mellékletek kizárása a következő útvonalakról, amikor a(z) {{command}} parancs végrehajtódik.\nMinden útvonalat új sorba írj.\n{{pathSyntax}}\nHa a beállítás üres, egyetlen útvonal sem kerül kizárásra a melléklet gyűjtésből.',
      name: 'Útvonalak kizárása a melléklet gyűjtésből'
    },
    generatedAttachmentFileName: {
      description: 'Lásd az elérhető {{tokens}}.',
      name: 'Generált melléklet fájlnév'
    },
    jpegQuality: {
      description: 'Minél kisebb a minőség, annál nagyobb a tömörítési arány.',
      name: 'JPEG minőség'
    },
    locationForNewAttachments: {
      description: 'A jegyzet szülőmappájához viszonyított relatív útvonalakhoz kezdd {{relativePrefix}} jelöléssel.\nLásd az elérhető {{tokens}}.\nA ponttal kezdődő mappák, mint a(z) {{dotFolder}}, nem ajánlottak, mert az Obsidian nem követi őket. A kezelésükhöz szükséged lehet a(z) {{unhidePlugin}} bővítményre.',
      name: 'Új mellékletek helye'
    },
    markdownUrlFormat: {
      description: 'A Markdown-ba beillesztendő URL formátuma, amikor melléklet kerül hozzáadásra. Csak abban a pillanatban érvényes: az a hivatkozás, amelyet az Obsidian később ír át egy jegyzet vagy melléklet átnevezésekor vagy áthelyezésekor, az alapértelmezett formátumot kapja.\nLásd az elérhető {{tokens}}.\nHagyd üresen az alapértelmezett formátum használatához.',
      name: 'Markdown URL formátum'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Alkalmazza-e a melléklet mappa és fájlnév beállításait a MÁS bővítmények által létrehozott mellékletekre.\nEgyes bővítmények saját néven írnak mellékletet a tárolóba, anélkül hogy megkérdeznék az Obsidiant, hová tartozik. Ha ez be van kapcsolva, az ilyen fájl a megjelenése után azonnal áthelyezésre és átnevezésre kerül.\nCsak azokat a fájlokat érinti, amelyek egy nyitott jegyzet mellett jöttek létre, és amelyekre jegyzet hivatkozik: az a fájl, amelyre egyetlen jegyzet sem hivatkozik, egy másik bővítmény saját adata, és ott marad, ahová írták. A szinkronizálásból vagy tárolóimportból érkező fájlokat soha nem érinti.\n{{modes}}\nA létrehozó bővítményt az írási művelet hívási verméből azonosítja. Ez nem mindig sikerül: nem azonosítható bővítmény az Obsidian által, egy szinkronizáló kliens által vagy az írását késleltető bővítmény által írt fájlnál. Az ilyen fájl úgy számít, mint ami NINCS az alábbi listában.',
      name: 'Más bővítmények által létrehozott mellékletek átnevezése'
    },
    renameAttachmentsToLowerCase: 'Mellékletek átnevezése kisbetűre',
    renamedAttachmentFileName: {
      description: 'Lásd az elérhető {{tokens}}.\nHagyd üresen a melléklet jelenlegi fájlnevének megtartásához.',
      name: 'Átnevezett melléklet fájlnév'
    },
    resetToSampleCustomTokens: {
      message: 'Biztosan visszaállítod az egyéni tokeneket a minta egyéni tokenekre? A változtatásaid elvesznek.',
      title: 'Visszaállítás minta egyéni tokenekre'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Beillesztett képek JPEG-re konvertálása. Csak akkor érvényes, amikor a PNG kép tartalma közvetlenül a vágólapról van beillesztve. Jellemzően képernyőképek beillesztésénél.',
      name: 'Beillesztett képek JPEG-re konvertálása'
    },
    shouldRenameCollectedAttachments: {
      description: 'Ha engedélyezve van, a(z) {{command}} parancsokkal feldolgozott mellékletek a(z) {{setting}} beállítás szerint lesznek átnevezve.',
      name: 'Gyűjtött mellékletek átnevezése'
    },
    specialCharacters: {
      description: 'A melléklet mappa- és fájlnevében cserélendő vagy eltávolítandó speciális karakterek.\nHagyd üresen a speciális karakterek megőrzéséhez.',
      name: 'Speciális karakterek'
    },
    specialCharactersReplacement: {
      description: 'Helyettesítő string a melléklet mappa- és fájlnevében lévő speciális karakterekhez.\nHagyd üresen a speciális karakterek eltávolításához.',
      name: 'Speciális karakterek helyettesítése'
    },
    timeoutInSeconds: {
      description: 'Az időtúllépés másodpercekben minden művelethez.\nHa {{zero}} van beállítva, a műveletek végrehajtási időtúllépése le van tiltva.',
      name: 'Időtúllépés másodpercekben'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Melléklet fájl átnevezése',
    folderTitle: 'Melléklet mappa kiválasztása',
    previewModal: {
      title: 'Melléklet fájl előnézete \'{{fullFileName}}\''
    },
    title: 'Adj meg egy értéket a prompt tokenhez'
  },
  regularExpression: '/reguláris kifejezés/'
};
