export const es = {
  attachmentCollector: {
    confirm: '¿Quieres recopilar de forma recursiva los archivos adjuntos de todas las notas de las siguientes carpetas?\n{{folders}}\nEsta operación no se puede deshacer.',
    progressBar: {
      message: 'Recopilando archivos adjuntos {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Recopilando archivos adjuntos...'
    }
  },
  buttons: {
    copy: 'Copiar',
    move: 'Mover',
    previewAttachmentFile: 'Vista previa del archivo adjunto',
    skip: 'Omitir'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'El archivo adjunto {{attachment}} está referenciado por múltiples notas.',
    heading: 'Recopilando archivo adjunto usado por múltiples notas',
    noPriorityWinnerReason: {
      EmptyList: 'No se movió porque la opción {{settingName}} está vacía, por lo que nada decide cuál de estas notas lo posee.',
      NoMatch: 'No se movió porque ninguna de estas notas coincide con ninguna entrada de la opción {{settingName}}.',
      Tie: 'No se movió porque varias de estas notas coinciden igual de bien con la opción {{settingName}}, por lo que no designa un único propietario.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Debería usar la misma acción para otros archivos adjuntos problemáticos'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Recopilar archivos adjuntos en la carpeta actual',
    collectAttachmentsCurrentNote: 'Recopilar archivos adjuntos en la nota actual',
    collectAttachmentsEntireVault: 'Recopilar archivos adjuntos en toda la bóveda'
  },
  links: {
    documentation: 'documentación',
    tokens: 'tokens'
  },
  menuItems: {
    collectAttachmentsInFile: 'Recopilar adjuntos en el archivo',
    collectAttachmentsInFiles: 'Recopilar adjuntos en los archivos'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Recopilando archivos adjuntos para \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Recopilación de archivos adjuntos cancelada. Ver consola para detalles.',
    generatedAttachmentFileNameIsInvalid: 'El nombre del archivo adjunto generado \'{{path}}\' no es válido.\n{{validationMessage}}\nRevisa la configuración {{settingName}}.',
    notePathIsIgnored: 'La ruta de la nota es ignorada'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Cancelar',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Elementos por página:',
      jumpToPage: 'Ir a página:'
    },
    notices: {
      attachmentIsStillUsed: 'El archivo adjunto {{attachmentPath}} aún es usado por otras notas. No será eliminado.',
      unhandledError: 'Ocurrió un error no manejado. Por favor revisa la consola para más información.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'todos los archivos son renombrados.',
        displayText: 'Todos'
      },
      none: {
        description: 'sus nombres son preservados.',
        displayText: 'Ninguno'
      },
      onlyPastedImages: {
        description: 'solo las imágenes pegadas son renombradas. Se aplica solo cuando el contenido de imagen PNG se pega directamente desde el portapapeles. Típicamente, para pegar capturas de pantalla.',
        displayText: 'Solo imágenes pegadas'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'cancelar la recopilación de archivos adjuntos.',
        displayText: 'Cancelar'
      },
      copy: {
        description: 'copiar el archivo adjunto a la nueva ubicación.',
        displayText: 'Copiar'
      },
      move: {
        description: 'mover el archivo adjunto a la nueva ubicación.',
        displayText: 'Mover'
      },
      prompt: {
        description: 'solicitar al usuario que elija la acción.',
        displayText: 'Solicitar'
      },
      skip: {
        description: 'omitir el archivo adjunto y proceder al siguiente.',
        displayText: 'Omitir'
      }
    },
    defaultImageSizeDimension: {
      height: 'Altura',
      width: 'Ancho'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Los tokens personalizados fueron comentados ya que deben ser actualizados al nuevo formato introducido en la versión del plugin 9.0.0.\n// Consulta la documentación ({{customTokensDocumentationUrl}}) para más información.',
      deprecated: 'El formato de registro de tokens personalizados cambió. Por favor actualiza tus tokens en consecuencia. Consulta la {{documentation}} para más información.'
    },
    legacyRenameAttachmentsToLowerCase: 'La configuración {{setting}} está obsoleta. Usa el formato {{format}} en su lugar. Consulta la {{documentation}} para más información.',
    markdownUrlFormat: {
      deprecated: 'Es posible que tengas un valor incorrecto establecido para el formato {{setting}}. Por favor consulta la {{documentation}} para más información. Este mensaje no se mostrará de nuevo.'
    },
    specialCharacters: 'Se cambió el valor por defecto de la configuración {{setting}}. Tu valor de configuración fue actualizado al nuevo valor por defecto.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'El tamaño de imagen predeterminado debe estar en píxeles o porcentaje',
      invalidCustomTokensCode: 'Código de tokens personalizados inválido',
      invalidRegularExpression: 'Expresión regular inválida {{regExp}}',
      specialCharactersMustNotContainSlash: 'Los caracteres especiales no deben contener /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'El reemplazo de caracteres especiales no debe contener caracteres de ruta de nombre de archivo inválidos.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Al adjuntar archivos:',
      name: 'Modo de renombrado de archivos adjuntos'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Cuando el archivo adjunto recopilado es usado por múltiples notas:',
      name: 'Modo de recopilar archivo adjunto usado por múltiples notas'
    },
    collectedAttachmentFileName: {
      description: 'Consulta los {{tokens}} disponibles.\nDejar vacío para mantener el nombre actual del archivo adjunto.',
      name: 'Nombre de archivo adjunto recopilado'
    },
    customTokens: {
      description: 'Tokens personalizados a usar.\nConsulta la {{documentation}} para más información.\n⚠️ Los tokens personalizados pueden ser código JavaScript arbitrario. Si están mal escritos, pueden causar pérdida de datos. Úsalos bajo tu propio riesgo.',
      name: 'Tokens personalizados'
    },
    defaultImageSize: {
      description: 'El tamaño de imagen predeterminado.\nPuede especificarse en píxeles ({{pixels}}) o como porcentaje del tamaño total de la imagen ({{percentage}}).\nDéjalo en blanco para usar el tamaño original de la imagen.',
      name: 'Tamaño de imagen predeterminado'
    },
    duplicateNameSeparator: {
      description: 'Cuando estás pegando/arrastrando un archivo con el mismo nombre que un archivo existente, este separador será añadido al nombre del archivo.\nPor ejemplo, cuando arrastras el archivo {{existingFile}}, será renombrado a {{firstAvailableName}}, {{secondAvailableName}}, etc., obteniendo el primer nombre disponible.',
      name: 'Separador de nombres duplicados'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Excluir archivos adjuntos de las siguientes rutas cuando se ejecuta el comando {{command}}.\nInserta cada ruta en una nueva línea.\n{{pathSyntax}}\nSi la configuración está vacía, no se excluyen rutas de la recopilación de archivos adjuntos.',
      name: 'Excluir rutas de la recopilación de archivos adjuntos'
    },
    generatedAttachmentFileName: {
      description: 'Consulta los {{tokens}} disponibles.',
      name: 'Nombre de archivo adjunto generado'
    },
    jpegQuality: {
      description: 'Cuanto menor la calidad, mayor la relación de compresión.',
      name: 'Calidad JPEG'
    },
    locationForNewAttachments: {
      description: 'Comienza con {{relativePrefix}} para rutas relativas a la carpeta que contiene la nota.\nConsulta los {{tokens}} disponibles.\nNo se recomiendan las carpetas con punto como {{dotFolder}}, porque Obsidian no las rastrea. Es posible que necesites el plugin {{unhidePlugin}} para gestionarlas.',
      name: 'Ubicación para nuevos archivos adjuntos'
    },
    markdownUrlFormat: {
      description: 'Formato para la URL que será insertada en Markdown al añadir un archivo adjunto. Solo se aplica en ese momento: un enlace que Obsidian reescribe más tarde, al renombrar o mover una nota o un archivo adjunto, recibe el formato por defecto.\nConsulta los {{tokens}} disponibles.\nDejar en blanco para usar el formato por defecto.',
      name: 'Formato de URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description:
        'Si se deben aplicar los ajustes de carpeta de adjuntos y nombre de archivo a los adjuntos que crean OTROS complementos.\nAlgunos complementos escriben un adjunto en la bóveda con un nombre propio, sin preguntar a Obsidian dónde corresponde. Con esta opción activada, ese archivo se mueve y se renombra en cuanto aparece.\nSolo se tocan los archivos creados mientras hay una nota abierta y enlazados desde una nota: un archivo al que ninguna nota enlaza contiene datos que otro complemento guarda para sí mismo y se queda donde se escribió. Los archivos que llegan de una sincronización o de una importación de bóveda nunca se tocan.\n{{modes}}\nEl complemento que crea el archivo se identifica a partir de la pila de llamadas de la escritura. Es una identificación aproximada: no se identifica ningún complemento para un archivo escrito por el propio Obsidian, por un cliente de sincronización o por un complemento que aplaza su escritura. Ese archivo cuenta como si NO estuviera en la lista de abajo.',
      name: 'Renombrar adjuntos creados por otros complementos'
    },
    renameAttachmentsToLowerCase: 'Renombrar archivos adjuntos a minúsculas',
    renamedAttachmentFileName: {
      description: 'Consulta los {{tokens}} disponibles.\nDejar vacío para mantener el nombre actual del archivo adjunto.',
      name: 'Nombre de archivo adjunto renombrado'
    },
    resetToSampleCustomTokens: {
      message: '¿Estás seguro de que quieres resetear los tokens personalizados a los tokens personalizados de muestra? Tus cambios se perderán.',
      title: 'Resetear a tokens personalizados de muestra'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Si convertir imágenes pegadas a JPEG. Se aplica solo cuando el contenido de imagen PNG se pega directamente desde el portapapeles. Típicamente, para pegar capturas de pantalla.',
      name: 'Si convertir imágenes pegadas a JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Si está habilitado, los archivos adjuntos procesados mediante los comandos {{command}} serán renombrados según la configuración {{setting}}.',
      name: 'Si renombrar archivos adjuntos recopilados'
    },
    specialCharacters: {
      description: 'Caracteres especiales en carpeta de archivos adjuntos y nombre de archivo a ser reemplazados o removidos.\nDejar en blanco para preservar caracteres especiales.',
      name: 'Caracteres especiales'
    },
    specialCharactersReplacement: {
      description: 'Cadena de reemplazo para caracteres especiales en carpeta de archivos adjuntos y nombre de archivo.\nDejar en blanco para remover caracteres especiales.',
      name: 'Reemplazo de caracteres especiales'
    },
    timeoutInSeconds: {
      description: 'El timeout en segundos para todas las operaciones.\nSi se establece {{zero}}, el timeout de ejecución de operaciones está deshabilitado.',
      name: 'Timeout en segundos'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Renombrar archivo adjunto',
    folderTitle: 'Elegir carpeta de adjuntos',
    previewModal: {
      title: 'Vista previa del archivo adjunto \'{{fullFileName}}\''
    },
    title: 'Proporciona un valor para el token de solicitud'
  },
  regularExpression: '/expresión regular/'
};
