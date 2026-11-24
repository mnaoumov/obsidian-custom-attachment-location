export const cs = {
  attachmentCollector: {
    confirm: 'Chcete shromáždit přílohy pro všechny poznámky ve složkách rekurzivně?\n{{folders}}\nTuto operaci nelze vrátit zpět.',
    progressBar: {
      message: 'Shromažďování příloh {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Shromažďování příloh...'
    }
  },
  buttons: {
    copy: 'Kopírovat',
    move: 'Přesunout',
    previewAttachmentFile: 'Náhled souboru přílohy',
    skip: 'Přeskočit'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Na přílohu {{attachment}} odkazuje více poznámek.',
    heading: 'Shromažďování přílohy používané více poznámkami',
    noPriorityWinnerReason: {
      EmptyList: 'Nebyla přesunuta, protože nastavení {{settingName}} je prázdné, takže nic nerozhoduje, které z těchto poznámek patří.',
      NoMatch: 'Nebyla přesunuta, protože žádná z těchto poznámek neodpovídá žádné položce v nastavení {{settingName}}.',
      Tie: 'Nebyla přesunuta, protože několik z těchto poznámek odpovídá nastavení {{settingName}} stejně dobře, takže neurčuje jediného vlastníka.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Měla by se použít stejná akce pro jiné problematické přílohy'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Shromáždit přílohy v aktuální složce',
    collectAttachmentsCurrentNote: 'Shromáždit přílohy v aktuální poznámce',
    collectAttachmentsEntireVault: 'Shromáždit přílohy v celém úložišti'
  },
  links: {
    documentation: 'dokumentaci',
    tokens: 'tokeny'
  },
  menuItems: {
    collectAttachmentsInFile: 'Shromáždit přílohy v souboru',
    collectAttachmentsInFiles: 'Shromáždit přílohy v souborech'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Shromažďování příloh pro \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Shromažďování příloh zrušeno. Podrobnosti viz konzole.',
    generatedAttachmentFileNameIsInvalid: 'Vygenerované jméno souboru přílohy \'{{path}}\' je neplatné.\n{{validationMessage}}\nZkontrolujte nastavení {{settingName}}.',
    notePathIsIgnored: 'Cesta poznámky je ignorována'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Zrušit',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Položek na stránku:',
      jumpToPage: 'Přejít na stránku:'
    },
    notices: {
      attachmentIsStillUsed: 'Příloha {{attachmentPath}} je stále používána jinými poznámkami. Nebude smazána.',
      unhandledError: 'Došlo k neošetřené chybě. Zkontrolujte prosím konzoli pro více informací.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'všechny soubory jsou přejmenovány.',
        displayText: 'Všechny'
      },
      none: {
        description: 'jejich názvy jsou zachovány.',
        displayText: 'Žádné'
      },
      onlyPastedImages: {
        description: 'přejmenovány jsou pouze vložené obrázky. Platí pouze když je obsah PNG obrázku vložen přímo ze schránky. Typicky pro vkládání snímků obrazovky.',
        displayText: 'Pouze vložené obrázky'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'zrušit shromažďování příloh.',
        displayText: 'Zrušit'
      },
      copy: {
        description: 'zkopírovat přílohu na nové umístění.',
        displayText: 'Kopírovat'
      },
      move: {
        description: 'přesunout přílohu na nové umístění.',
        displayText: 'Přesunout'
      },
      prompt: {
        description: 'vyzvat uživatele k výběru akce.',
        displayText: 'Výzva'
      },
      skip: {
        description: 'přeskočit přílohu a pokračovat k další.',
        displayText: 'Přeskočit'
      }
    },
    defaultImageSizeDimension: {
      height: 'Výška',
      width: 'Šířka'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Vlastní tokeny byly zakomentovány, protože musí být aktualizovány na nový formát zavedený ve verzi pluginu 9.0.0.\n// Odkazujte na dokumentaci ({{customTokensDocumentationUrl}}) pro více informací.',
      deprecated: 'Formát registrace vlastních tokenů se změnil. Aktualizujte prosím své tokeny odpovídajícím způsobem. Další informace najdete v {{documentation}}.'
    },
    legacyRenameAttachmentsToLowerCase: 'Nastavení {{setting}} je zastaralé. Použijte místo něj formát {{format}}. Další informace najdete v {{documentation}}.',
    markdownUrlFormat: {
      deprecated: 'Pro formát {{setting}} máte možná nastavenou nesprávnou hodnotu. Další informace najdete v {{documentation}}. Tato zpráva se již nebude zobrazovat.'
    },
    specialCharacters: 'Výchozí hodnota nastavení {{setting}} se změnila. Vaše hodnota nastavení byla aktualizována na novou výchozí hodnotu.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Výchozí velikost obrázku musí být v pixelech nebo procentech',
      invalidCustomTokensCode: 'Neplatný kód vlastních tokenů',
      invalidRegularExpression: 'Neplatný regulární výraz {{regExp}}',
      specialCharactersMustNotContainSlash: 'Speciální znaky nesmí obsahovat /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Náhrada speciálních znaků nesmí obsahovat neplatné znaky cesty názvu souboru.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Při připojování souborů:',
      name: 'Režim přejmenování příloh'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Když je shromážděná příloha používána více poznámkami:',
      name: 'Režim shromažďování přílohy používané více poznámkami'
    },
    collectedAttachmentFileName: {
      description: 'Viz dostupné {{tokens}}.\nPonechte prázdné, chcete-li zachovat aktuální jméno souboru přílohy.',
      name: 'Jméno souboru shromážděné přílohy'
    },
    customTokens: {
      description: 'Vlastní tokeny k použití.\nDalší informace najdete v {{documentation}}.\n⚠️ Vlastní tokeny mohou být libovolný JavaScript kód. Pokud jsou špatně napsané, mohou způsobit ztrátu dat. Používejte je na vlastní riziko.',
      name: 'Vlastní tokeny'
    },
    defaultImageSize: {
      description: 'Výchozí velikost obrázku.\nLze ji zadat v pixelech ({{pixels}}) nebo jako procento z plné velikosti obrázku ({{percentage}}).\nPonechte prázdné, chcete-li použít původní velikost obrázku.',
      name: 'Výchozí velikost obrázku'
    },
    duplicateNameSeparator: {
      description: 'Když vkládáte/přetahujete soubor se stejným názvem jako existující soubor, tento oddělovač bude přidán k názvu souboru.\nNapř. když přetáhnete soubor {{existingFile}}, bude přejmenován na {{firstAvailableName}}, {{secondAvailableName}} atd., podle prvního dostupného názvu.',
      name: 'Oddělovač duplicitních názvů'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Vyloučit přílohy z následujících cest při spuštění příkazu {{command}}.\nVložte každou cestu na nový řádek.\n{{pathSyntax}}\nPokud je nastavení prázdné, žádné cesty nejsou vyloučeny ze shromažďování příloh.',
      name: 'Vyloučit cesty ze shromažďování příloh'
    },
    generatedAttachmentFileName: {
      description: 'Viz dostupné {{tokens}}.',
      name: 'Vygenerované jméno souboru přílohy'
    },
    jpegQuality: {
      description: 'Čím menší kvalita, tím větší kompresní poměr.',
      name: 'Kvalita JPEG'
    },
    locationForNewAttachments: {
      description: 'Začněte s {{relativePrefix}} pro cesty relativní k nadřazené složce poznámky.\nViz dostupné {{tokens}}.\nTečkové složky jako {{dotFolder}} nejsou doporučeny, protože Obsidian je nesleduje. Ke správě těchto složek možná budete potřebovat plugin {{unhidePlugin}}.',
      name: 'Umístění pro nové přílohy'
    },
    markdownUrlFormat: {
      description: 'Formát URL, které bude vloženo do Markdownu při přidání přílohy. Použije se pouze v tu chvíli: odkaz, který Obsidian později přepíše při přejmenování nebo přesunu poznámky či přílohy, dostane výchozí formát.\nViz dostupné {{tokens}}.\nPonechte prázdné pro použití výchozího formátu.',
      name: 'Formát URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Zda použít nastavení složky příloh a názvu souboru na přílohy, které vytvářejí JINÉ pluginy.\nNěkteré pluginy zapíší přílohu do trezoru pod vlastním názvem, aniž by se Obsidianu zeptaly, kam patří. Je-li tato volba zapnutá, takový soubor se hned po vzniku přesune a přejmenuje.\nZpracují se jen soubory vzniklé při otevřené poznámce, na které odkazuje nějaká poznámka: soubor, na který neodkazuje žádná poznámka, jsou data, která si jiný plugin uchovává pro sebe, a zůstane tam, kam byl zapsán. Soubory přicházející ze synchronizace nebo z importu trezoru se nikdy nezpracují.\n{{modes}}\nPlugin, který soubor vytvořil, se určuje ze zásobníku volání zápisu. Jde jen o odhad: u souboru, který zapsal sám Obsidian, synchronizační klient nebo plugin, který zápis odkládá, se žádný plugin neurčí. Takový soubor se počítá, jako by v seznamu níže NEBYL.',
      name: 'Přejmenovat přílohy vytvořené jinými pluginy'
    },
    renameAttachmentsToLowerCase: 'Přejmenovat přílohy na malá písmena',
    renamedAttachmentFileName: {
      description: 'Viz dostupné {{tokens}}.\nPonechte prázdné, chcete-li zachovat aktuální jméno souboru přílohy.',
      name: 'Jméno souboru přejmenované přílohy'
    },
    resetToSampleCustomTokens: {
      message: 'Jste si jisti, že chcete resetovat vlastní tokeny na ukázkové vlastní tokeny? Vaše změny budou ztraceny.',
      title: 'Resetovat na ukázkové vlastní tokeny'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Zda převést vložené obrázky na JPEG. Platí pouze když je obsah PNG obrázku vložen přímo ze schránky. Typicky pro vkládání snímků obrazovky.',
      name: 'Zda převést vložené obrázky na JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Pokud je povoleno, přílohy zpracované příkazy {{command}} budou přejmenovány podle nastavení {{setting}}.',
      name: 'Zda přejmenovat shromážděné přílohy'
    },
    specialCharacters: {
      description: 'Speciální znaky v názvu složky příloh a souboru, které se mají nahradit nebo odstranit.\nPonechte prázdné pro zachování speciálních znaků.',
      name: 'Speciální znaky'
    },
    specialCharactersReplacement: {
      description: 'Náhradní řetězec pro speciální znaky v názvu složky příloh a souboru.\nPonechte prázdné pro odstranění speciálních znaků.',
      name: 'Náhrada speciálních znaků'
    },
    timeoutInSeconds: {
      description: 'Časový limit v sekundách pro všechny operace.\nPokud je nastaveno {{zero}}, časový limit provádění operací je zakázán.',
      name: 'Časový limit v sekundách'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Přejmenovat soubor přílohy',
    folderTitle: 'Vyberte složku příloh',
    previewModal: {
      title: 'Náhled souboru přílohy \'{{fullFileName}}\''
    },
    title: 'Poskytněte hodnotu pro token výzvy'
  },
  regularExpression: '/regulární výraz/'
};
