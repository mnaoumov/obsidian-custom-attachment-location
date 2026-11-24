export const fr = {
  attachmentCollector: {
    confirm: 'Voulez-vous collecter de manière récursive les pièces jointes de toutes les notes des dossiers suivants ?\n{{folders}}\nCette opération ne peut pas être annulée.',
    progressBar: {
      message: 'Collecte des pièces jointes {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Collecte des pièces jointes...'
    }
  },
  buttons: {
    copy: 'Copier',
    move: 'Déplacer',
    previewAttachmentFile: 'Aperçu du fichier joint',
    skip: 'Ignorer'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'La pièce jointe {{attachment}} est référencée par plusieurs notes.',
    heading: 'Collecte de pièce jointe utilisée par plusieurs notes',
    noPriorityWinnerReason: {
      EmptyList: 'Elle n\'a pas été déplacée car le paramètre {{settingName}} est vide, donc rien ne décide à laquelle de ces notes elle appartient.',
      NoMatch: 'Elle n\'a pas été déplacée car aucune de ces notes ne correspond à une entrée du paramètre {{settingName}}.',
      Tie: 'Elle n\'a pas été déplacée car plusieurs de ces notes correspondent aussi bien au paramètre {{settingName}}, qui ne désigne donc aucun propriétaire unique.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Utiliser la même action pour les autres pièces jointes problématiques'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Collecter les pièces jointes dans le dossier actuel',
    collectAttachmentsCurrentNote: 'Collecter les pièces jointes dans la note actuelle',
    collectAttachmentsEntireVault: 'Collecter les pièces jointes dans tout le coffre'
  },
  links: {
    documentation: 'documentation',
    tokens: 'jetons'
  },
  menuItems: {
    collectAttachmentsInFile: 'Collecter les pièces jointes dans le fichier',
    collectAttachmentsInFiles: 'Collecter les pièces jointes dans les fichiers'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Collecte des pièces jointes pour \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Collecte des pièces jointes annulée. Voir la console pour plus de détails.',
    generatedAttachmentFileNameIsInvalid: 'Le nom de fichier de pièce jointe généré \'{{path}}\' est invalide.\n{{validationMessage}}\nVérifiez votre paramètre {{settingName}}.',
    notePathIsIgnored: 'Le chemin de la note est ignoré'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Annuler',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Éléments par page :',
      jumpToPage: 'Aller à la page :'
    },
    notices: {
      attachmentIsStillUsed: 'La pièce jointe {{attachmentPath}} est encore utilisée par d\'autres notes. Elle ne sera pas supprimée.',
      unhandledError: 'Une erreur non gérée s\'est produite. Veuillez vérifier la console pour plus d\'informations.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'tous les fichiers sont renommés.',
        displayText: 'Tous'
      },
      none: {
        description: 'leurs noms sont préservés.',
        displayText: 'Aucun'
      },
      onlyPastedImages: {
        description: 'seules les images collées sont renommées. S\'applique uniquement lorsque le contenu d\'image PNG est collé directement depuis le presse-papiers. Typiquement, pour coller des captures d\'\u{E9}cran.',
        displayText: 'Images collées uniquement'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'annuler la collecte de pièces jointes.',
        displayText: 'Annuler'
      },
      copy: {
        description: 'copier la pièce jointe vers le nouvel emplacement.',
        displayText: 'Copier'
      },
      move: {
        description: 'déplacer la pièce jointe vers le nouvel emplacement.',
        displayText: 'Déplacer'
      },
      prompt: {
        description: 'demander à l\'utilisateur de choisir l\'action.',
        displayText: 'Demander'
      },
      skip: {
        description: 'ignorer la pièce jointe et passer à la suivante.',
        displayText: 'Ignorer'
      }
    },
    defaultImageSizeDimension: {
      height: 'Hauteur',
      width: 'Largeur'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Les jetons personnalisés ont été commentés car ils doivent être mis à jour vers le nouveau format introduit dans la version 9.0.0 du plugin.\n// Consultez la documentation ({{customTokensDocumentationUrl}}) pour plus d\'informations.',
      deprecated: 'Le format d\'enregistrement des jetons personnalisés a changé. Veuillez mettre à jour vos jetons en conséquence. Consultez la {{documentation}} pour plus d\'informations.'
    },
    legacyRenameAttachmentsToLowerCase: 'Le paramètre {{setting}} est obsolète. Utilisez plutôt le format {{format}}. Consultez la {{documentation}} pour plus d\'informations.',
    markdownUrlFormat: {
      deprecated: 'La valeur définie pour le format {{setting}} est peut-être incorrecte. Veuillez consulter la {{documentation}} pour plus d\'informations. Ce message ne sera plus affiché.'
    },
    specialCharacters: 'La valeur par défaut du paramètre {{setting}} a été modifiée. Votre valeur de paramètre a été mise à jour vers la nouvelle valeur par défaut.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'La taille d\'image par défaut doit être en pixels ou en pourcentage',
      invalidCustomTokensCode: 'Code de jetons personnalisés invalide',
      invalidRegularExpression: 'Expression régulière invalide {{regExp}}',
      specialCharactersMustNotContainSlash: 'Les caractères spéciaux ne doivent pas contenir /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Le remplacement des caractères spéciaux ne doit pas contenir de caractères de chemin de fichier invalides.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Lors de l\'ajout de fichiers :',
      name: 'Mode de renommage des pièces jointes'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Lorsque la pièce jointe collectée est utilisée par plusieurs notes :',
      name: 'Mode de collecte de pièce jointe utilisée par plusieurs notes'
    },
    collectedAttachmentFileName: {
      description: 'Voir les {{tokens}} disponibles.\nLaisser vide pour conserver le nom actuel du fichier de pièce jointe.',
      name: 'Nom de fichier de pièce jointe collectée'
    },
    customTokens: {
      description: 'Jetons personnalisés à utiliser.\nVoir la {{documentation}} pour plus d\'informations.\n⚠️ Les jetons personnalisés peuvent être du code JavaScript arbitraire. S\'ils sont mal écrits, ils peuvent causer une perte de données. Utilisez-les à vos propres risques.',
      name: 'Jetons personnalisés'
    },
    defaultImageSize: {
      description: 'La taille d\'image par défaut.\nPeut être spécifiée en pixels ({{pixels}}) ou en pourcentage de la taille totale de l\'image ({{percentage}}).\nLaissez vide pour utiliser la taille originale.',
      name: 'Taille d\'image par défaut'
    },
    duplicateNameSeparator: {
      description: 'Lorsque vous collez/glissez un fichier avec le même nom qu\'un fichier existant, ce séparateur sera ajouté au nom du fichier.\nPar exemple, lorsque vous glissez le fichier {{existingFile}}, il sera renommé en {{firstAvailableName}}, {{secondAvailableName}}, etc., selon le premier nom disponible.',
      name: 'Séparateur de nom dupliqué'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Exclure les pièces jointes des chemins suivants lorsque la commande {{command}} est exécutée.\nInsérez chaque chemin sur une nouvelle ligne.\n{{pathSyntax}}\nSi le paramètre est vide, aucun chemin n\'est exclu de la collecte de pièces jointes.',
      name: 'Chemins exclus de la collecte de pièces jointes'
    },
    generatedAttachmentFileName: {
      description: 'Voir les {{tokens}} disponibles.',
      name: 'Nom de fichier de pièce jointe généré'
    },
    jpegQuality: {
      description: 'Plus la qualité est faible, plus le taux de compression est élevé.',
      name: 'Qualité JPEG'
    },
    locationForNewAttachments: {
      description: 'Commencez par {{relativePrefix}} pour un chemin relatif au dossier parent de la note.\nVoir les {{tokens}} disponibles.\nLes dossiers point comme {{dotFolder}} ne sont pas recommandés, car Obsidian ne les suit pas. Vous pourriez avoir besoin du plugin {{unhidePlugin}} pour les gérer.',
      name: 'Emplacement des nouvelles pièces jointes'
    },
    markdownUrlFormat: {
      description: 'Format de l\'URL qui sera insérée dans Markdown lors de l\'ajout d\'une pièce jointe. Il ne s\'applique qu\'à ce moment-là : un lien qu\'Obsidian réécrit plus tard, lorsqu\'une note ou une pièce jointe est renommée ou déplacée, reçoit le format par défaut.\nVoir les {{tokens}} disponibles.\nLaisser vide pour utiliser le format par défaut.',
      name: 'Format d\'URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description:
        'Appliquer ou non les réglages de dossier de pièces jointes et de nom de fichier aux pièces jointes créées par D\'AUTRES modules.\nCertains modules écrivent une pièce jointe dans le coffre sous un nom de leur choix, sans demander à Obsidian où elle doit aller. Avec cette option, un tel fichier est déplacé et renommé dès son apparition.\nSeuls les fichiers créés pendant qu\'une note est ouverte, et liés depuis une note, sont concernés : un fichier vers lequel aucune note ne pointe contient des données qu\'un autre module conserve pour lui-même, et il reste là où il a été écrit. Les fichiers provenant d\'une synchronisation ou d\'un import de coffre ne sont jamais concernés.\n{{modes}}\nLe module créateur est identifié à partir de la pile d\'appels de l\'écriture. Cette identification est approximative : aucun module n\'est identifié pour un fichier écrit par Obsidian lui-même, par un client de synchronisation ou par un module qui diffère son écriture. Un tel fichier est considéré comme ne figurant PAS dans la liste ci-dessous.',
      name: 'Renommer les pièces jointes créées par d\'autres modules'
    },
    renameAttachmentsToLowerCase: 'Renommer les pièces jointes en minuscules',
    renamedAttachmentFileName: {
      description: 'Voir les {{tokens}} disponibles.\nLaisser vide pour conserver le nom actuel du fichier de pièce jointe.',
      name: 'Nom de fichier de pièce jointe renommée'
    },
    resetToSampleCustomTokens: {
      message: 'Êtes-vous sûr de vouloir réinitialiser les jetons personnalisés aux jetons personnalisés d\'exemple ? Vos modifications seront perdues.',
      title: 'Réinitialiser aux jetons personnalisés d\'exemple'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Convertir les images collées en JPEG. S\'applique uniquement lorsque le contenu d\'image PNG est collé directement depuis le presse-papiers. Typiquement, pour coller des captures d\'écran.',
      name: 'Convertir les images collées en JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Si activé, les pièces jointes traitées via les commandes {{command}} seront renommées selon le paramètre {{setting}}.',
      name: 'Renommer les pièces jointes collectées'
    },
    specialCharacters: {
      description: 'Caractères spéciaux dans le dossier de pièces jointes et le nom de fichier à remplacer ou supprimer.\nLaisser vide pour préserver les caractères spéciaux.',
      name: 'Caractères spéciaux'
    },
    specialCharactersReplacement: {
      description: 'Chaîne de remplacement pour les caractères spéciaux dans le dossier de pièces jointes et le nom de fichier.\nLaisser vide pour supprimer les caractères spéciaux.',
      name: 'Remplacement des caractères spéciaux'
    },
    timeoutInSeconds: {
      description: 'Le délai d\'expiration en secondes pour toutes les opérations.\nSi {{zero}} est défini, le délai d\'expiration de l\'exécution des opérations est désactivé.',
      name: 'Délai d\'expiration en secondes'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Renommer le fichier de pièce jointe',
    folderTitle: 'Choisir le dossier des pièces jointes',
    previewModal: {
      title: 'Aperçu du fichier de pièce jointe \'{{fullFileName}}\''
    },
    title: 'Fournir une valeur pour le jeton de saisie'
  },
  regularExpression: '/expression régulière/'
};
