export const ca = {
  attachmentCollector: {
    confirm: 'Vols recopilar els adjunts de totes les notes de les carpetes de manera recursiva?\n{{folders}}\nAquesta operació no es pot desfer.',
    progressBar: {
      message: 'Recollint adjunts {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Recollint adjunts...'
    }
  },
  buttons: {
    copy: 'Copiar',
    move: 'Moure',
    previewAttachmentFile: 'Previsualitzar fitxer adjunt',
    skip: 'Ometre'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'L\'adjunt {{attachment}} és referenciat per múltiples notes.',
    heading: 'Recollint adjunt utilitzat per múltiples notes',
    noPriorityWinnerReason: {
      EmptyList: 'No s\'ha mogut perquè el paràmetre {{settingName}} és buit, de manera que res no decideix quina d\'aquestes notes el posseeix.',
      NoMatch: 'No s\'ha mogut perquè cap d\'aquestes notes no coincideix amb cap entrada del paràmetre {{settingName}}.',
      Tie: 'No s\'ha mogut perquè diverses d\'aquestes notes coincideixen igual de bé amb el paràmetre {{settingName}}, de manera que no n\'anomena cap propietari únic.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Ha d\'utilitzar la mateixa acció per a altres adjunts problemàtics'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Recollir adjunts a la carpeta actual',
    collectAttachmentsCurrentNote: 'Recollir adjunts a la nota actual',
    collectAttachmentsEntireVault: 'Recollir adjunts a tot el dipòsit'
  },
  links: {
    documentation: 'documentació',
    tokens: 'tokens'
  },
  menuItems: {
    collectAttachmentsInFile: 'Recopila els adjunts al fitxer',
    collectAttachmentsInFiles: 'Recopila els adjunts als fitxers'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Recollint adjunts per a \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Recollida d\'adjunts cancel·lada. Vegeu la consola per a detalls.',
    generatedAttachmentFileNameIsInvalid: 'El nom del fitxer adjunt generat \'{{path}}\' no és vàlid.\n{{validationMessage}}\nComproveu la configuració {{settingName}}.',
    notePathIsIgnored: 'El camí de la nota s\'ignora'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Cancel·lar',
      ok: 'D\'acord'
    },
    dataview: {
      itemsPerPage: 'Elements per pàgina:',
      jumpToPage: 'Saltar a la pàgina:'
    },
    notices: {
      attachmentIsStillUsed: 'L\'adjunt {{attachmentPath}} encara s\'utilitza per altres notes. No s\'esborrarà.',
      unhandledError: 'S\'ha produït un error no gestionat. Si us plau, comproveu la consola per a més informació.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'tots els fitxers es reanomenen.',
        displayText: 'Tots'
      },
      none: {
        description: 'els seus noms es preserven.',
        displayText: 'Cap'
      },
      onlyPastedImages: {
        description: 'només les imatges enganxades es reanomenen. S\'aplica només quan el contingut de la imatge PNG s\'enganxa directament des del porta-retalls. Típicament, per enganxar captures de pantalla.',
        displayText: 'Només imatges enganxades'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'cancel·lar la recollida d\'adjunts.',
        displayText: 'Cancel·lar'
      },
      copy: {
        description: 'copiar l\'adjunt a la nova ubicació.',
        displayText: 'Copiar'
      },
      move: {
        description: 'moure l\'adjunt a la nova ubicació.',
        displayText: 'Moure'
      },
      prompt: {
        description: 'preguntar a l\'usuari per triar l\'acció.',
        displayText: 'Preguntar'
      },
      skip: {
        description: 'ometre l\'adjunt i procedir al següent.',
        displayText: 'Ometre'
      }
    },
    defaultImageSizeDimension: {
      height: 'Alçada',
      width: 'Amplada'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Els tokens personalitzats van ser comentats ja que han de ser actualitzats al nou format introduït a la versió del plugin 9.0.0.\n// Consulteu la documentació ({{customTokensDocumentationUrl}}) per a més informació.',
      deprecated: 'El format de registre de tokens personalitzats ha canviat. Si us plau, actualitzeu els vostres tokens en conseqüència. Consulteu la {{documentation}} per a més informació.'
    },
    legacyRenameAttachmentsToLowerCase: 'La configuració {{setting}} està obsoleta. Utilitzeu el format {{format}} en lloc seu. Vegeu la {{documentation}} per a més informació.',
    markdownUrlFormat: {
      deprecated: 'Potser teniu un valor incorrecte establert per al format {{setting}}. Consulteu la {{documentation}} per a més informació. Aquest missatge no es mostrarà de nou.'
    },
    specialCharacters: 'El valor per defecte de la configuració {{setting}} ha canviat. El vostre valor de configuració s\'ha actualitzat al nou valor per defecte.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'La mida predeterminada de la imatge s\'ha d\'expressar en píxels o percentatge',
      invalidCustomTokensCode: 'Codi de tokens personalitzats no vàlid',
      invalidRegularExpression: 'Expressió regular no vàlida {{regExp}}',
      specialCharactersMustNotContainSlash: 'Els caràcters especials no han de contenir /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'El reemplaçament de caràcters especials no ha de contenir caràcters de camí de nom de fitxer no vàlids.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Quan s\'adjunten fitxers:',
      name: 'Mode de reanomenament d\'adjunts'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Quan l\'adjunt recollit és utilitzat per múltiples notes:',
      name: 'Mode de recollida d\'adjunt utilitzat per múltiples notes'
    },
    collectedAttachmentFileName: {
      description: 'Vegeu els {{tokens}} disponibles.\nDeixeu-ho buit per mantenir el nom actual del fitxer adjunt.',
      name: 'Nom de fitxer adjunt recollit'
    },
    customTokens: {
      description: 'Tokens personalitzats a utilitzar.\nVegeu la {{documentation}} per a més informació.\n⚠️ Els tokens personalitzats poden ser codi JavaScript arbitrari. Si estan mal escrits, poden causar pèrdua de dades. Utilitzeu-los sota la vostra responsabilitat.',
      name: 'Tokens personalitzats'
    },
    defaultImageSize: {
      description: 'La mida predeterminada de la imatge.\nEs pot especificar en píxels ({{pixels}}) o en percentatge de la mida completa de la imatge ({{percentage}}).\nDeixeu-ho en blanc per utilitzar la mida original de la imatge.',
      name: 'Mida predeterminada de la imatge'
    },
    duplicateNameSeparator: {
      description: 'Quan enganxeu/arrossegueu un fitxer amb el mateix nom que un fitxer existent, aquest separador s\'afegirà al nom del fitxer.\nPer exemple, quan arrossegueu el fitxer {{existingFile}}, es reanomenarà a {{firstAvailableName}}, {{secondAvailableName}}, etc., i s\'agafarà el primer nom disponible.',
      name: 'Separador de noms duplicats'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Exclou els adjunts dels camins següents quan s\'executa la comanda {{command}}.\nInseriu cada camí en una línia nova.\n{{pathSyntax}}\nSi la configuració està buida, cap camí no s\'exclou de la recollida d\'adjunts.',
      name: 'Excloure camins de la recollida d\'adjunts'
    },
    generatedAttachmentFileName: {
      description: 'Vegeu els {{tokens}} disponibles.',
      name: 'Nom de fitxer adjunt generat'
    },
    jpegQuality: {
      description: 'Com més petita la qualitat, més gran la relació de compressió.',
      name: 'Qualitat JPEG'
    },
    locationForNewAttachments: {
      description: 'Comenceu amb {{relativePrefix}} per a camins relatius a la carpeta pare de la nota.\nVegeu els {{tokens}} disponibles.\nLes carpetes amb punt com {{dotFolder}} no es recomanen, perquè Obsidian no les rastreja. Potser necessiteu el plugin {{unhidePlugin}} per gestionar-les.',
      name: 'Ubicació per a nous adjunts'
    },
    markdownUrlFormat: {
      description: 'Format per a l\'URL que s\'inserirà a Markdown quan s\'afegeixi un adjunt. Només s\'aplica en aquell moment: un enllaç que Obsidian reescrigui més tard, quan es reanomeni o es mogui una nota o un adjunt, rep el format per defecte.\nVegeu els {{tokens}} disponibles.\nDeixeu-ho buit per utilitzar el format per defecte.',
      name: 'Format URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Si cal aplicar la configuració de carpeta d\'adjunts i de nom de fitxer als adjunts que creen ALTRES connectors.\nAlguns connectors escriuen un adjunt al magatzem amb un nom propi, sense preguntar a Obsidian on correspon. Amb això activat, aquest fitxer es mou i es reanomena tot just apareix.\nNomés s\'afecten els fitxers creats amb una nota oberta i enllaçats des d\'una nota: un fitxer que cap nota no enllaça són dades que un altre connector guarda per a si mateix, i es queda on s\'ha escrit. Els fitxers que arriben d\'una sincronització o d\'una importació de magatzem no es toquen mai.\n{{modes}}\nEl connector creador s\'identifica a partir de la pila de crides de l\'escriptura. És una aproximació: no s\'identifica cap connector per a un fitxer escrit pel mateix Obsidian, per un client de sincronització o per un connector que ajorna l\'escriptura. Un fitxer així compta com a NO inclòs a la llista següent.',
      name: 'Reanomena els adjunts creats per altres connectors'
    },
    renameAttachmentsToLowerCase: 'Reanomenar adjunts a minúscules',
    renamedAttachmentFileName: {
      description: 'Vegeu els {{tokens}} disponibles.\nDeixeu-ho buit per mantenir el nom actual del fitxer adjunt.',
      name: 'Nom de fitxer adjunt reanomenat'
    },
    resetToSampleCustomTokens: {
      message: 'Esteu segurs que voleu restablir els tokens personalitzats als tokens personalitzats de mostra? Les vostres canvis es perdran.',
      title: 'Restablir als tokens personalitzats de mostra'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Si convertir les imatges enganxades a JPEG. S\'aplica només quan el contingut de la imatge PNG s\'enganxa directament des del porta-retalls. Típicament, per enganxar captures de pantalla.',
      name: 'Si convertir les imatges enganxades a JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Si està habilitat, els adjunts processats per les comandes {{command}} es reanomenaran segons la configuració {{setting}}.',
      name: 'Si reanomenar adjunts recollits'
    },
    specialCharacters: {
      description: 'Caràcters especials del nom de la carpeta d\'adjunts i del fitxer que s\'han de reemplaçar o eliminar.\nDeixeu-ho buit per preservar els caràcters especials.',
      name: 'Caràcters especials'
    },
    specialCharactersReplacement: {
      description: 'Cadena de reemplaçament per als caràcters especials del nom de la carpeta d\'adjunts i del fitxer.\nDeixeu-ho buit per eliminar els caràcters especials.',
      name: 'Reemplaçament de caràcters especials'
    },
    timeoutInSeconds: {
      description: 'El temps d\'espera en segons per a totes les operacions.\nSi s\'estableix {{zero}}, el temps d\'espera d\'execució de les operacions es desactiva.',
      name: 'Temps d\'espera en segons'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Reanomena el fitxer adjunt',
    folderTitle: 'Tria la carpeta d\'adjunts',
    previewModal: {
      title: 'Previsualitzar fitxer adjunt \'{{fullFileName}}\''
    },
    title: 'Proporcioneu un valor per al token de sol·licitud'
  },
  regularExpression: '/expressió regular/'
};
