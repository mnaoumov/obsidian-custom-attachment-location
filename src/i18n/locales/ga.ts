export const ga = {
  attachmentCollector: {
    confirm: 'Ar mhaith leat na ceangaltáin a bhailiú go hathchúrsach do gach nóta sna fillteáin seo a leanas?\n{{folders}}\nNí féidir an oibríocht seo a chealú.',
    progressBar: {
      message: 'Ag bailiú ceangaltán {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Ag bailiú ceangaltán...'
    }
  },
  buttons: {
    copy: 'Cóipeáil',
    move: 'Bog',
    previewAttachmentFile: 'Réamhamharc comhad ceangaltáin',
    skip: 'Léim thar'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Tá an ceangaltán {{attachment}} in úsáid ag nótaí iomadúla.',
    heading: 'Ag bailiú ceangaltáin atá in úsáid ag nótaí iomadúla',
    noPriorityWinnerReason: {
      EmptyList: 'Níor bogadh é toisc go bhfuil an socrú {{settingName}} folamh, mar sin níl aon rud a chinneann cé acu de na nótaí seo ar leis é.',
      NoMatch: 'Níor bogadh é toisc nach bhfuil aon cheann de na nótaí seo ag teacht le hiontráil ar bith sa socrú {{settingName}}.',
      Tie: 'Níor bogadh é toisc go bhfuil roinnt de na nótaí seo ag teacht leis an socrú {{settingName}} chomh maith céanna, mar sin ní ainmníonn sé aon úinéir amháin.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Ba chóir an gníomh céanna a úsáid do cheangaltáin fhadhbach eile'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Bailigh ceangaltáin san fhillteán reatha',
    collectAttachmentsCurrentNote: 'Bailigh ceangaltáin sa nóta reatha',
    collectAttachmentsEntireVault: 'Bailigh ceangaltáin sa taisc iomplán'
  },
  links: {
    documentation: 'doiciméadú',
    tokens: 'comharthaí'
  },
  menuItems: {
    collectAttachmentsInFile: 'Bailigh ceangaltáin sa chomhad',
    collectAttachmentsInFiles: 'Bailigh ceangaltáin sna comhaid'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Ag bailiú ceangaltán do \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Cealaigh bailiú ceangaltán. Féach ar an consól le haghaidh sonraí.',
    generatedAttachmentFileNameIsInvalid: 'Tá ainm comhad ceangaltáin ginte \'{{path}}\' neamhbhailí.\n{{validationMessage}}\nSeiceáil do shocrú {{settingName}}.',
    notePathIsIgnored: 'Tá conair an nóta á neamhaird'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Cealaigh',
      ok: 'Tá go maith'
    },
    dataview: {
      itemsPerPage: 'Míreanna in aghaidh na leathanach:',
      jumpToPage: 'Léim chuig leathanach:'
    },
    notices: {
      attachmentIsStillUsed: 'Tá ceangaltán {{attachmentPath}} fós in úsáid ag nótaí eile. Ní scriosfar é.',
      unhandledError: 'Tharla earráid nár láimhseáladh. Seiceáil an consól le haghaidh tuilleadh eolais.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'tá na comhaid go léir athainmnithe.',
        displayText: 'Uile'
      },
      none: {
        description: 'tá a n-ainmneacha caomhnaithe.',
        displayText: 'Dada'
      },
      onlyPastedImages: {
        description: 'ní athainmnítear ach íomhánna greamaithe. Bainean seo leis nuair a ghreamaitear ábhair íomhá PNG ón ghearrtáisce go díreach. Go típúl, chun grênghrafaí a ghreamadh.',
        displayText: 'Íomhánna greamaithe amháin'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'cealaigh bailiú ceangaltán.',
        displayText: 'Cealaigh'
      },
      copy: {
        description: 'cóipeáil an ceangaltán chuig an suíomh nua.',
        displayText: 'Cóipeáil'
      },
      move: {
        description: 'bog an ceangaltán chuig an suíomh nua.',
        displayText: 'Bog'
      },
      prompt: {
        description: 'cuir an t-úsáideoir faoi deara an gníomh a roghnú.',
        displayText: 'Cuir faoi deara'
      },
      skip: {
        description: 'léim thar an ceangaltán agus lean ar aghaidh chuig an chéad cheann eile.',
        displayText: 'Léim thar'
      }
    },
    defaultImageSizeDimension: {
      height: 'Airde',
      width: 'Leithead'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Cuireadh comharthaí saincheaptha i gcomhrá mar gheall ar gá iad a nuashonrú chuig an fhormáid nua a tugadh isteach i leagan 9.0.0 an phlugain.\n// Féach ar an doiciméadú ({{customTokensDocumentationUrl}}) le haghaidh tuilleadh eolais.',
      deprecated: 'D\'athraigh formáid chlárúcháin na gcomharthaí saincheaptha. Nuashonraigh do chomharthaí dá réir. Féach ar an {{documentation}} le haghaidh tuilleadh eolais.'
    },
    legacyRenameAttachmentsToLowerCase: 'Tá an socrú {{setting}} as feidhm. Úsáid an fhormáid {{format}} ina ionad. Féach ar an {{documentation}} le haghaidh tuilleadh eolais.',
    markdownUrlFormat: {
      deprecated: 'D\'fhéadfadh go bhfuil luach mícheart socraithe agat don fhormáid {{setting}}. Féach ar an {{documentation}} le haghaidh tuilleadh eolais. Ní thaispeánfar an teachtaireacht seo arís.'
    },
    specialCharacters: 'Athraíodh luach réamhshocraithe an tsocraithe {{setting}}. Nuashonraíodh do luach socraithe chuig an luach réamhshocraithe nua.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Caithfidh méid réamhshocraithe na híomhá a bheith i bpicteilíní nó i gcéatadán',
      invalidCustomTokensCode: 'Cód comharthaí saincheaptha neamhbhailí',
      invalidRegularExpression: 'Slonn rialta neamhbhailí {{regExp}}',
      specialCharactersMustNotContainSlash: 'Níor cheart go mbeadh / sna carachtair speisialta',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Níor cheart go mbeadh carachtair conair ainm comhaid neamhbhailí in ionadú carachtar speisialta.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Nuair a bhíonn comhaid á gceangal:',
      name: 'Mód athainmnithe ceangaltán'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Nuair a bhíonn an ceangaltán bailithe in úsáid ag nótaí iomadúla:',
      name: 'Mód bailiú ceangaltán atá in úsáid ag nótaí iomadúla'
    },
    collectedAttachmentFileName: {
      description: 'Féach ar na {{tokens}} atá ar fáil.\nFág folamh chun ainm reatha an chomhaid ceangaltáin a choinneáil.',
      name: 'Ainm comhad ceangaltán bailithe'
    },
    customTokens: {
      description: 'Comharthaí saincheaptha le húsáid.\nFéach ar an {{documentation}} le haghaidh tuilleadh eolais.\n⚠️ Is féidir le comharthaí saincheaptha a bheith ina chód JavaScript treallach. Má tá siad drochscríofa, is féidir leo cailliúint sonraí a chur faoi deara. Úsáid iad ar do riosca féin.',
      name: 'Comharthaí saincheaptha'
    },
    defaultImageSize: {
      description: 'Méid réamhshocraithe na híomhá.\nIs féidir é a shonrú i bpicteilíní ({{pixels}}) nó i gcéatadán de mhéid na híomhá iomláine ({{percentage}}).\nFág folamh chun an méid bunaidh a úsáid.',
      name: 'Méid réamhshocraithe na híomhá'
    },
    duplicateNameSeparator: {
      description: 'Nuair a bhíonn tú ag greamú/tarraingt comhaid leis an ainm céanna le comhad atá ann cheana, cuirfear an deighilteoir seo leis an ainm comhaid.\nM.sh., nuair a tharraingíonn tú an comhad {{existingFile}}, athainmneofar é go {{firstAvailableName}}, {{secondAvailableName}}, srl., ag fáil an chéad ainm atá ar fáil.',
      name: 'Deighilteoir ainm dúbailte'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Eisigh ceangaltáin ó na conairí seo a leanas nuair a fhorghníomhaítear an t-ordú {{command}}.\nCuir isteach gach conair ar líne nua.\n{{pathSyntax}}\nMá tá an socrú folamh, ní eisítear aon chonair ó bhailiú ceangaltán.',
      name: 'Conairí a eisíomh ó bhailiú ceangaltán'
    },
    generatedAttachmentFileName: {
      description: 'Féach ar na {{tokens}} atá ar fáil.',
      name: 'Ainm comhad ceangaltán ginte'
    },
    jpegQuality: {
      description: 'Dá laghad an cáilíocht, is mó an cóimheas comhbhrú.',
      name: 'Cáilíocht JPEG'
    },
    locationForNewAttachments: {
      description: 'Tosaigh le {{relativePrefix}} le haghaidh conairí atá coibhneasta le fillteán tuismitheora an nóta.\nFéach ar na {{tokens}} atá ar fáil.\nNí mholtar fillteáin phonc mar {{dotFolder}}, mar ní rianaíonn Obsidian iad. D\'fhéadfadh go mbeadh an plugan {{unhidePlugin}} de dhíth ort chun iad a bhainistiú.',
      name: 'Suíomh do cheangaltáin nua'
    },
    markdownUrlFormat: {
      description: 'Formáid don URL a chuirfear isteach i Markdown nuair a chuirtear ceangaltán leis. Ní chuirtear i bhfeidhm í ach an tráth sin: faigheann nasc a athscríobhann Obsidian níos déanaí, nuair a athainmnítear nó a bhogtar nóta nó ceangaltán, an fhormáid réamhshocraithe.\nFéach ar na {{tokens}} atá ar fáil.\nFág bán chun an fhormáid réamhshocraithe a úsáid.',
      name: 'Formáid URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description:
        'Cé acu na socruithe fillteáin ceangaltán agus ainm comhaid a chur i bhfeidhm ar cheangaltáin a chruthaíonn breiseáin EILE.\nScríobhann roinnt breiseán ceangaltán isteach sa taisce faoi ainm dá gcuid féin, gan fiafraí d\'Obsidian cá mbaineann sé. Agus é seo ar siúl, bogtar agus athainmnítear comhad den sórt sin díreach tar éis dó teacht chun cinn.\nNí bhaintear ach le comhaid a chruthaítear agus nóta ar oscailt, agus a bhfuil nasc chucu ó nóta: is sonraí a choinníonn breiseán eile dó féin atá i gcomhad nach bhfuil nasc chuige ó aon nóta, agus fanann sé san áit ar scríobhadh é. Ní bhaintear riamh le comhaid a thagann ó shioncronú nó ó iompórtáil taisce.\n{{modes}}\nAithnítear an breiseán a chruthaigh an comhad ó chruach glaonna na scríbhneoireachta. Ní dhéantar é sin ach chomh maith agus is féidir: ní aithnítear aon bhreiseán do chomhad a scríobh Obsidian féin, cliant sioncronaithe, nó breiseán a chuireann a scríbhneoireacht siar. Meastar NACH bhfuil comhad den sórt sin sa liosta thíos.',
      name: 'Athainmnigh ceangaltáin a chruthaíonn breiseáin eile'
    },
    renameAttachmentsToLowerCase: 'Athainmnigh ceangaltáin go litreacha beaga',
    renamedAttachmentFileName: {
      description: 'Féach ar na {{tokens}} atá ar fáil.\nFág folamh chun ainm reatha an chomhaid ceangaltáin a choinneáil.',
      name: 'Ainm comhad ceangaltán athainmnithe'
    },
    resetToSampleCustomTokens: {
      message: 'An bhfuil tú cinnte gur mhaith leat na comharthaí saincheaptha a athshocrú chuig na comharthaí saincheaptha samplacha? Caillfear do athruithe.',
      title: 'Athshocraigh chuig comharthaí saincheaptha samplacha'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Cibé an gcaithfear íomhánna greamaithe a thiontú go JPEG. Baineann seo leis nuair a ghreamaitear ábhair íomhá PNG ón ghearrtáisce go díreach. Go típúl, chun grênghrafaí a ghreamadh.',
      name: 'An gcaithfear íomhánna greamaithe a thiontú go JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Má tá sé cumasaithe, athainmneofar ceangaltáin a phróiseáiltear trí na horduithe {{command}} de réir an tsocraithe {{setting}}.',
      name: 'An gcaithfear ceangaltáin bailithe a athainmniú'
    },
    specialCharacters: {
      description: 'Carachtair speisialta i bhfillteán ceangaltán agus ainm comhaid le cur in ionad nó a bhaint.\nFág bán chun carachtair speisialta a chaomhnú.',
      name: 'Carachtair speisialta'
    },
    specialCharactersReplacement: {
      description: 'Teaghrán ionadaíochta do charachtair speisialta i bhfillteán ceangaltán agus ainm comhaid.\nFág bán chun carachtair speisialta a bhaint.',
      name: 'Ionadú carachtar speisialta'
    },
    timeoutInSeconds: {
      description: 'An t-am amach i soicindí do gach oibríocht.\nMá tá {{zero}} socraithe, díchumasaítear an t-am amach d\'fhorghníomhú oibríochtaí.',
      name: 'T-am amach i soicindí'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Athainmnigh comhad ceangaltáin',
    folderTitle: 'Roghnaigh fillteán ceangaltán',
    previewModal: {
      title: 'Réamhamharc comhad ceangaltáin \'{{fullFileName}}\''
    },
    title: 'Soláthair luach don chomhartha cuir faoi deara'
  },
  regularExpression: '/slonn rialta/'
};
