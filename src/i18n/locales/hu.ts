export const hu = {
  attachmentCollector: {
    confirm: {
      part1: 'Szeretnéd összegyűjteni a mellékleteket a mappákban lévő összes jegyzethez rekurzívan?',
      part2: 'Ez a művelet nem vonható vissza.'
    },
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
    content: {
      part1: 'Melléklet',
      part2: 'több jegyzet hivatkozik rá.'
    },
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
  menuItems: {
    collectAttachmentsInFile: 'Mellékletek összegyűjtése a fájlban',
    collectAttachmentsInFiles: 'Mellékletek összegyűjtése a fájlokban'
  },
  notice: {
    collectingAttachments: 'Mellékletek gyűjtése a következőhöz: \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Melléklet gyűjtés megszakítva. Részletekért lásd a konzolt.',
    generatedAttachmentFileNameIsInvalid: {
      part1: 'A generált melléklet fájlnév \'{{path}}\' érvénytelen.\n{{validationMessage}}\nEllenőrizd a',
      part2: 'beállításodat.'
    },
    notePathIsIgnored: 'A jegyzet elérési útja figyelmen kívül marad'
  },
  obsidianDevUtils: {
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
      codeComment: '// Az egyéni tokenek kommentbe kerültek, mert frissíteni kell őket a 9.0.0 verzióban bevezetett új formátumra.\n// További információért lásd a dokumentációt (https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#custom-tokens).',
      deprecated: {
        part1: 'A 9.0.0 verzióban az egyéni token regisztráció formátuma megváltozott. Kérjük, frissítsd a tokenjeidet ennek megfelelően. Lásd a',
        part2: 'dokumentációt',
        part3: 'további információért'
      }
    },
    legacyRenameAttachmentsToLowerCase: {
      part1: 'A 9.0.0 verzióban a',
      part2: 'beállítás elavult. Használd a',
      part3: 'formátumot helyette. Lásd a',
      part4: 'dokumentációt',
      part5: 'további információért'
    },
    markdownUrlFormat: {
      deprecated: {
        part1: 'Lehet, hogy hibás értéket állítottál be a',
        part2: 'formátumhoz. Kérjük, lásd a',
        part3: 'dokumentációt',
        part4: 'további információért',
        part5: 'Ez az üzenet nem jelenik meg újra.'
      }
    },
    specialCharacters: {
      part1: 'A 9.16.0 verzióban a',
      part2: 'alapértelmezett beállítási érték megváltozott. A beállítási értéked frissítésre került az új alapértelmezett értékre.'
    },
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
      description: {
        part1: 'Fájlok csatolásakor:'
      },
      name: 'Melléklet átnevezési mód'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: {
        part1: 'Amikor a gyűjtött mellékletet több jegyzet használja:'
      },
      name: 'Több jegyzet által használt melléklet gyűjtési mód'
    },
    collectedAttachmentFileName: {
      description: {
        part1: 'Lásd az elérhető',
        part2: 'tokeneket',
        part3: 'Hagyd üresen az eredeti melléklet fájlnév megtartásához.'
      },
      name: 'Gyűjtött melléklet fájlnév'
    },
    customTokens: {
      description: {
        part1: 'Használandó egyéni tokenek.',
        part2: 'Lásd a',
        part3: 'dokumentációt',
        part4: 'további információért.',
        part5: '⚠️ Az egyéni tokenek tetszőleges JavaScript kód lehetnek. Ha rosszul írták, adatvesztést okozhatnak. Saját felelősségre használd.'
      },
      name: 'Egyéni tokenek'
    },
    defaultImageSize: {
      description: {
        part1: 'Az alapértelmezett képméret.',
        part2: 'Meghatározható pixelben',
        part3: 'vagy a teljes képméret százalékában',
        part4: 'Hagyja üresen az eredeti méret használatához.'
      },
      name: 'Alapértelmezett képméret'
    },
    duplicateNameSeparator: {
      description: {
        part1: 'Amikor egy meglévő fájllal azonos nevű fájlt illesztesz be/húzol, ez az elválasztó kerül hozzáadásra a fájlnévhez.',
        part2: 'Pl. amikor a fájlt',
        part3: 'húzod, átnevezésre kerül',
        part4: 'stb., az első elérhető nevet kapva.'
      },
      name: 'Duplikált név elválasztó'
    },
    excludePathsFromAttachmentCollecting: {
      description: {
        part1: 'Mellékletek kizárása a következő útvonalakból, amikor a',
        part2: 'Mellékletek gyűjtése',
        part3: 'parancs végrehajtódik.',
        part4: 'Minden útvonalat új sorba írj.',
        part5: 'Használhatsz útvonal stringet vagy',
        part6: 'Ha a beállítás üres, egyetlen útvonal sem kerül kizárásra a melléklet gyűjtésből.'
      },
      name: 'Útvonalak kizárása a melléklet gyűjtésből'
    },
    generatedAttachmentFileName: {
      description: {
        part1: 'Lásd az elérhető',
        part2: 'tokeneket'
      },
      name: 'Generált melléklet fájlnév'
    },
    jpegQuality: {
      description: 'Minél kisebb a minőség, annál nagyobb a tömörítési arány.',
      name: 'JPEG minőség'
    },
    locationForNewAttachments: {
      description: {
        part1: 'Kezdd a',
        part2: 'jelöléssel relatív útvonal használatához.',
        part3: 'Lásd az elérhető',
        part4: 'tokeneket',
        part5: 'Pont mappák, mint a',
        part6: 'nem ajánlottak, mert az Obsidian nem követi őket. Szükséged lehet',
        part7: 'bővítményre a kezelésükhöz.'
      },
      name: 'Új mellékletek helye'
    },
    markdownUrlFormat: {
      description: {
        part1: 'Formátum a Markdown-ba beillesztendő URL-hez.',
        part2: 'Lásd az elérhető',
        part3: 'tokeneket',
        part4: 'Hagyd üresen az alapértelmezett formátum használatához.'
      },
      name: 'Markdown URL formátum'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: {
        part1: 'Alkalmazza-e a melléklet mappa és fájlnév beállításait a MÁS bővítmények által létrehozott mellékletekre.',
        part2: 'Egyes bővítmények saját néven írnak mellékletet a tárolóba, anélkül hogy megkérdeznék az Obsidiant, hová tartozik. Ha ez be van kapcsolva, az ilyen fájl a megjelenése után azonnal átkerül és átnevezésre kerül.',
        part3: 'Csak a nyitott jegyzet mellett létrejövő fájlokat érinti, a szinkronizálásból vagy tárolóimportból érkezőket soha.'
      },
      name: 'Más bővítmények által létrehozott mellékletek átnevezése'
    },
    renameAttachmentsToLowerCase: 'Mellékletek átnevezése kisbetűre',
    renamedAttachmentFileName: {
      description: {
        part1: 'Lásd az elérhető',
        part2: 'tokeneket',
        part3: 'Hagyd üresen az eredeti melléklet fájlnév megtartásához.'
      },
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
      description: {
        part1: 'Ha engedélyezve, a',
        part2: 'Mellékletek gyűjtése',
        part3: 'parancsokon keresztül feldolgozott mellékletek átnevezésre kerülnek a',
        part4: 'beállítás szerint.'
      },
      name: 'Gyűjtött mellékletek átnevezése'
    },
    specialCharacters: {
      description: {
        part1: 'Speciális karakterek a melléklet mappában és fájlnévben cserélendő vagy eltávolítandó.',
        part2: 'Hagyd üresen a speciális karakterek megőrzéséhez.'
      },
      name: 'Speciális karakterek'
    },
    specialCharactersReplacement: {
      description: {
        part1: 'Helyettesítő string a speciális karakterekhez a melléklet mappában és fájlnévben.',
        part2: 'Hagyd üresen a speciális karakterek eltávolításához.'
      },
      name: 'Speciális karakterek helyettesítése'
    },
    timeoutInSeconds: {
      description: {
        part1: 'Az időtúllépés másodpercekben minden művelethez.',
        part2: 'Ha',
        part3: 'be van állítva, a műveletek végrehajtási időtúllépése le van tiltva.'
      },
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
